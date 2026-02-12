/*
 * HexCore SQLite3 - Native Node.js Bindings
 * SQLite3 Wrapper Implementation
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "sqlite3_wrapper.h"
#include <cstring>
#include <cassert>

// ============================================================================
// DatabaseWrapper
// ============================================================================

Napi::FunctionReference DatabaseWrapper::constructor;

Napi::Object DatabaseWrapper::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "Database", {
		InstanceMethod("prepare", &DatabaseWrapper::Prepare),
		InstanceMethod("exec", &DatabaseWrapper::Exec),
		InstanceMethod("close", &DatabaseWrapper::Close),
		InstanceMethod("pragma", &DatabaseWrapper::Pragma),
		InstanceMethod("loadExtension", &DatabaseWrapper::LoadExtension),
		InstanceMethod("defaultSafeIntegers", &DatabaseWrapper::DefaultSafeIntegers),
		InstanceAccessor("name", &DatabaseWrapper::GetName, nullptr),
		InstanceAccessor("open", &DatabaseWrapper::GetOpen, nullptr),
		InstanceAccessor("inTransaction", &DatabaseWrapper::GetInTransaction, nullptr),
		InstanceAccessor("readonly", &DatabaseWrapper::GetReadonly, nullptr),
		InstanceAccessor("memory", &DatabaseWrapper::GetMemory, nullptr),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();
	exports.Set("Database", func);
	return exports;
}

DatabaseWrapper::DatabaseWrapper(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<DatabaseWrapper>(info)
	, db_(nullptr)
	, open_(false)
	, readonly_(false)
	, memory_(false)
	, safeIntegers_(false)
{
	Napi::Env env = info.Env();

	// Args: filename, filenameGiven, anonymous, readonly, fileMustExist, timeout, verbose, buffer
	// We support the simplified form: (filename, anonymous, readonly, fileMustExist, timeout)
	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Expected filename as first argument").ThrowAsJavaScriptException();
		return;
	}

	std::string filename = info[0].As<Napi::String>().Utf8Value();
	name_ = filename;

	bool isAnonymous = filename.empty() || filename == ":memory:";
	memory_ = isAnonymous;

	bool isReadonly = false;
	bool fileMustExist = false;
	int timeout = 5000;

	// Parse remaining args if provided (positional: filenameGiven, anonymous, readonly, fileMustExist, timeout, verbose, buffer)
	if (info.Length() >= 4 && info[3].IsBoolean()) {
		isReadonly = info[3].As<Napi::Boolean>().Value();
	}
	if (info.Length() >= 5 && info[4].IsBoolean()) {
		fileMustExist = info[4].As<Napi::Boolean>().Value();
	}
	if (info.Length() >= 6 && info[5].IsNumber()) {
		timeout = info[5].As<Napi::Number>().Int32Value();
	}

	readonly_ = isReadonly;

	int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
	if (isReadonly) {
		flags = SQLITE_OPEN_READONLY;
	}
	if (isAnonymous) {
		flags |= SQLITE_OPEN_MEMORY;
	}

	int rc = sqlite3_open_v2(filename.c_str(), &db_, flags, nullptr);
	if (rc != SQLITE_OK) {
		std::string msg = db_ ? sqlite3_errmsg(db_) : "Failed to open database";
		if (db_) { sqlite3_close(db_); db_ = nullptr; }
		Napi::Error::New(env, msg).ThrowAsJavaScriptException();
		return;
	}

	open_ = true;

	// Set busy timeout
	sqlite3_busy_timeout(db_, timeout);

	// Enable extended result codes
	sqlite3_extended_result_codes(db_, 1);

	// Set safe limits
	sqlite3_limit(db_, SQLITE_LIMIT_LENGTH, INT32_MAX);

	// Handle buffer (deserialize) if provided
	if (info.Length() >= 8 && info[7].IsBuffer()) {
		Napi::Buffer<uint8_t> buf = info[7].As<Napi::Buffer<uint8_t>>();
		size_t len = buf.Length();
		unsigned char* data = static_cast<unsigned char*>(sqlite3_malloc64(len));
		if (!data) {
			Napi::Error::New(env, "Out of memory").ThrowAsJavaScriptException();
			return;
		}
		memcpy(data, buf.Data(), len);
		rc = sqlite3_deserialize(db_, "main", data, len, len,
			SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE);
		if (rc != SQLITE_OK) {
			ThrowSqliteError(env, rc);
			return;
		}
	}
}

DatabaseWrapper::~DatabaseWrapper() {
	if (db_) {
		// Finalize all tracked statements
		for (auto* stmt : statements_) {
			stmt->FinalizeStatement();
		}
		statements_.clear();
		sqlite3_close(db_);
		db_ = nullptr;
	}
}

void DatabaseWrapper::TrackStatement(StatementWrapper* stmt) {
	statements_.insert(stmt);
}

void DatabaseWrapper::UntrackStatement(StatementWrapper* stmt) {
	statements_.erase(stmt);
}

void DatabaseWrapper::ThrowSqliteError(Napi::Env env) {
	ThrowSqliteError(env, sqlite3_errcode(db_));
}

void DatabaseWrapper::ThrowSqliteError(Napi::Env env, int rc) {
	const char* msg = db_ ? sqlite3_errmsg(db_) : "Unknown SQLite error";
	Napi::Error err = Napi::Error::New(env, msg);
	err.Set("code", Napi::String::New(env, sqlite3_errstr(rc)));
	err.ThrowAsJavaScriptException();
}

Napi::Value DatabaseWrapper::Exec(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (!open_) {
		Napi::TypeError::New(env, "The database connection is not open").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Expected a string").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	std::string sql = info[0].As<Napi::String>().Utf8Value();
	char* errMsg = nullptr;
	int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg);
	if (rc != SQLITE_OK) {
		std::string msg = errMsg ? errMsg : "SQL execution failed";
		if (errMsg) sqlite3_free(errMsg);
		Napi::Error err = Napi::Error::New(env, msg);
		err.Set("code", Napi::String::New(env, sqlite3_errstr(rc)));
		err.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	return info.This();
}

Napi::Value DatabaseWrapper::Prepare(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (!open_) {
		Napi::TypeError::New(env, "The database connection is not open").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Expected a string").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Create a StatementWrapper via its JS constructor
	Napi::Object stmtObj = StatementWrapper::constructor.New({
		info[0],                                    // sql
		info.This(),                                // database reference
		Napi::Boolean::New(env, safeIntegers_),     // inherit safeIntegers
	});

	return stmtObj;
}

Napi::Value DatabaseWrapper::Close(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (db_) {
		for (auto* stmt : statements_) {
			stmt->FinalizeStatement();
		}
		statements_.clear();
		sqlite3_close(db_);
		db_ = nullptr;
		open_ = false;
	}
	return info.This();
}

Napi::Value DatabaseWrapper::Pragma(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (!open_) {
		Napi::TypeError::New(env, "The database connection is not open").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Expected a string").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	std::string pragmaStr = "PRAGMA " + info[0].As<Napi::String>().Utf8Value();
	bool simple = false;
	if (info.Length() >= 2 && info[1].IsObject()) {
		Napi::Object opts = info[1].As<Napi::Object>();
		if (opts.Has("simple") && opts.Get("simple").IsBoolean()) {
			simple = opts.Get("simple").As<Napi::Boolean>().Value();
		}
	}

	sqlite3_stmt* stmt = nullptr;
	int rc = sqlite3_prepare_v2(db_, pragmaStr.c_str(), -1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		ThrowSqliteError(env, rc);
		return env.Undefined();
	}

	if (simple) {
		rc = sqlite3_step(stmt);
		Napi::Value result;
		if (rc == SQLITE_ROW) {
			int type = sqlite3_column_type(stmt, 0);
			switch (type) {
				case SQLITE_INTEGER:
					result = Napi::Number::New(env, static_cast<double>(sqlite3_column_int64(stmt, 0)));
					break;
				case SQLITE_TEXT:
					result = Napi::String::New(env, reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
					break;
				default:
					result = env.Null();
					break;
			}
		} else {
			result = env.Undefined();
		}
		sqlite3_finalize(stmt);
		return result;
	}

	// Return array of rows
	Napi::Array rows = Napi::Array::New(env);
	uint32_t idx = 0;
	int cols = sqlite3_column_count(stmt);
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		Napi::Object row = Napi::Object::New(env);
		for (int c = 0; c < cols; c++) {
			const char* colName = sqlite3_column_name(stmt, c);
			int type = sqlite3_column_type(stmt, c);
			switch (type) {
				case SQLITE_INTEGER:
					row.Set(colName, Napi::Number::New(env, static_cast<double>(sqlite3_column_int64(stmt, c))));
					break;
				case SQLITE_FLOAT:
					row.Set(colName, Napi::Number::New(env, sqlite3_column_double(stmt, c)));
					break;
				case SQLITE_TEXT:
					row.Set(colName, Napi::String::New(env, reinterpret_cast<const char*>(sqlite3_column_text(stmt, c))));
					break;
				case SQLITE_BLOB: {
					const void* data = sqlite3_column_blob(stmt, c);
					int len = sqlite3_column_bytes(stmt, c);
					row.Set(colName, Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(data), len));
					break;
				}
				default:
					row.Set(colName, env.Null());
					break;
			}
		}
		rows.Set(idx++, row);
	}
	sqlite3_finalize(stmt);
	return rows;
}

Napi::Value DatabaseWrapper::LoadExtension(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (!open_) {
		Napi::TypeError::New(env, "The database connection is not open").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "Expected a string").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	std::string extPath = info[0].As<Napi::String>().Utf8Value();
	const char* entryPoint = nullptr;
	if (info.Length() >= 2 && info[1].IsString()) {
		static std::string ep;
		ep = info[1].As<Napi::String>().Utf8Value();
		entryPoint = ep.c_str();
	}

	sqlite3_db_config(db_, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 1, nullptr);
	char* errMsg = nullptr;
	int rc = sqlite3_load_extension(db_, extPath.c_str(), entryPoint, &errMsg);
	if (rc != SQLITE_OK) {
		std::string msg = errMsg ? errMsg : "Failed to load extension";
		if (errMsg) sqlite3_free(errMsg);
		Napi::Error::New(env, msg).ThrowAsJavaScriptException();
		return env.Undefined();
	}

	return info.This();
}

Napi::Value DatabaseWrapper::DefaultSafeIntegers(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (info.Length() >= 1 && info[0].IsBoolean()) {
		safeIntegers_ = info[0].As<Napi::Boolean>().Value();
	} else {
		safeIntegers_ = true;
	}
	return info.This();
}

// Property getters
Napi::Value DatabaseWrapper::GetName(const Napi::CallbackInfo& info) {
	return Napi::String::New(info.Env(), name_);
}
Napi::Value DatabaseWrapper::GetOpen(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), open_);
}
Napi::Value DatabaseWrapper::GetInTransaction(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), db_ ? !sqlite3_get_autocommit(db_) : false);
}
Napi::Value DatabaseWrapper::GetReadonly(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), readonly_);
}
Napi::Value DatabaseWrapper::GetMemory(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), memory_);
}

// ============================================================================
// StatementWrapper
// ============================================================================

Napi::FunctionReference StatementWrapper::constructor;

Napi::Object StatementWrapper::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "Statement", {
		InstanceMethod("run", &StatementWrapper::Run),
		InstanceMethod("get", &StatementWrapper::Get),
		InstanceMethod("all", &StatementWrapper::All),
		InstanceMethod("iterate", &StatementWrapper::Iterate),
		InstanceMethod("columns", &StatementWrapper::Columns),
		InstanceMethod("bind", &StatementWrapper::Bind),
		InstanceMethod("safeIntegers", &StatementWrapper::SafeIntegers),
		InstanceMethod("raw", &StatementWrapper::Raw),
		InstanceMethod("expand", &StatementWrapper::Expand),
		InstanceAccessor("source", &StatementWrapper::GetSource, nullptr),
		InstanceAccessor("reader", &StatementWrapper::GetReader, nullptr),
		InstanceAccessor("busy", &StatementWrapper::GetBusy, nullptr),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();
	exports.Set("Statement", func);
	return exports;
}

StatementWrapper::StatementWrapper(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<StatementWrapper>(info)
	, stmt_(nullptr)
	, db_(nullptr)
	, finalized_(false)
	, safeIntegers_(false)
	, rawMode_(false)
	, expandMode_(false)
{
	Napi::Env env = info.Env();

	if (info.Length() < 2 || !info[0].IsString() || !info[1].IsObject()) {
		Napi::TypeError::New(env, "Expected (sql, database)").ThrowAsJavaScriptException();
		return;
	}

	source_ = info[0].As<Napi::String>().Utf8Value();
	db_ = Napi::ObjectWrap<DatabaseWrapper>::Unwrap(info[1].As<Napi::Object>());

	if (!db_ || !db_->IsOpened()) {
		Napi::TypeError::New(env, "The database connection is not open").ThrowAsJavaScriptException();
		return;
	}

	// Inherit safeIntegers from database
	if (info.Length() >= 3 && info[2].IsBoolean()) {
		safeIntegers_ = info[2].As<Napi::Boolean>().Value();
	}

	int rc = sqlite3_prepare_v2(db_->GetHandle(), source_.c_str(), -1, &stmt_, nullptr);
	if (rc != SQLITE_OK) {
		db_->ThrowSqliteError(env, rc);
		return;
	}

	db_->TrackStatement(this);
}

StatementWrapper::~StatementWrapper() {
	// Intentionally empty — cleanup is done in FinalizeStatement()
	// which is called either by DatabaseWrapper::Close/~DatabaseWrapper
	// or by the GC via Napi prevent double-free.
}

void StatementWrapper::Finalize(Napi::Env /*env*/) {
	FinalizeStatement();
}

void StatementWrapper::FinalizeStatement() {
	if (stmt_ && !finalized_) {
		sqlite3_finalize(stmt_);
		stmt_ = nullptr;
		finalized_ = true;
		if (db_) {
			db_->UntrackStatement(this);
			db_ = nullptr;
		}
	}
}

void StatementWrapper::BindValue(Napi::Env env, int index, Napi::Value val) {
	int rc;
	if (val.IsNull() || val.IsUndefined()) {
		rc = sqlite3_bind_null(stmt_, index);
	} else if (val.IsNumber()) {
		double d = val.As<Napi::Number>().DoubleValue();
		if (d == static_cast<double>(static_cast<int64_t>(d)) && d >= -9007199254740991.0 && d <= 9007199254740991.0) {
			rc = sqlite3_bind_int64(stmt_, index, static_cast<int64_t>(d));
		} else {
			rc = sqlite3_bind_double(stmt_, index, d);
		}
	} else if (val.IsString()) {
		std::string s = val.As<Napi::String>().Utf8Value();
		rc = sqlite3_bind_text(stmt_, index, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT);
	} else if (val.IsBigInt()) {
		bool lossless;
		int64_t v = val.As<Napi::BigInt>().Int64Value(&lossless);
		rc = sqlite3_bind_int64(stmt_, index, v);
	} else if (val.IsBuffer()) {
		Napi::Buffer<uint8_t> buf = val.As<Napi::Buffer<uint8_t>>();
		rc = sqlite3_bind_blob(stmt_, index, buf.Data(), static_cast<int>(buf.Length()), SQLITE_TRANSIENT);
	} else {
		Napi::TypeError::New(env, "SQLite3 can only bind numbers, strings, bigints, buffers, and null").ThrowAsJavaScriptException();
		return;
	}
	if (rc != SQLITE_OK) {
		db_->ThrowSqliteError(env, rc);
	}
}

void StatementWrapper::BindParams(Napi::Env env, const Napi::CallbackInfo& info, int startIdx) {
	sqlite3_reset(stmt_);
	sqlite3_clear_bindings(stmt_);

	int paramCount = sqlite3_bind_parameter_count(stmt_);
	if (paramCount == 0) return;

	int argIdx = startIdx;
	// If first arg is an object (named params) or array
	if (static_cast<int>(info.Length()) > argIdx && info[argIdx].IsObject() && !info[argIdx].IsBuffer() && !info[argIdx].IsArray()) {
		Napi::Object obj = info[argIdx].As<Napi::Object>();
		for (int i = 1; i <= paramCount; i++) {
			const char* paramName = sqlite3_bind_parameter_name(stmt_, i);
			if (paramName) {
				// Skip the prefix character (: @ $)
				std::string key(paramName + 1);
				if (obj.Has(key)) {
					BindValue(env, i, obj.Get(key));
				}
			}
		}
	} else {
		// Positional binding
		for (int i = 1; i <= paramCount && argIdx < static_cast<int>(info.Length()); i++, argIdx++) {
			BindValue(env, i, info[argIdx]);
		}
	}
}

Napi::Value StatementWrapper::ColumnToJS(Napi::Env env, int col) {
	int type = sqlite3_column_type(stmt_, col);
	switch (type) {
		case SQLITE_INTEGER: {
			int64_t v = sqlite3_column_int64(stmt_, col);
			if (safeIntegers_) {
				return Napi::BigInt::New(env, v);
			}
			return Napi::Number::New(env, static_cast<double>(v));
		}
		case SQLITE_FLOAT:
			return Napi::Number::New(env, sqlite3_column_double(stmt_, col));
		case SQLITE_TEXT:
			return Napi::String::New(env, reinterpret_cast<const char*>(sqlite3_column_text(stmt_, col)));
		case SQLITE_BLOB: {
			const void* data = sqlite3_column_blob(stmt_, col);
			int len = sqlite3_column_bytes(stmt_, col);
			return Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(data), len);
		}
		default:
			return env.Null();
	}
}

Napi::Object StatementWrapper::RowToObject(Napi::Env env) {
	int cols = sqlite3_column_count(stmt_);
	if (expandMode_) {
		// Group by table name
		Napi::Object result = Napi::Object::New(env);
		for (int c = 0; c < cols; c++) {
			const char* table = sqlite3_column_table_name(stmt_, c);
			const char* colName = sqlite3_column_name(stmt_, c);
			std::string tableName = table ? table : "$";
			if (!result.Has(tableName)) {
				result.Set(tableName, Napi::Object::New(env));
			}
			result.Get(tableName).As<Napi::Object>().Set(colName, ColumnToJS(env, c));
		}
		return result;
	}

	Napi::Object row = Napi::Object::New(env);
	for (int c = 0; c < cols; c++) {
		row.Set(sqlite3_column_name(stmt_, c), ColumnToJS(env, c));
	}
	return row;
}

Napi::Array StatementWrapper::RowToArray(Napi::Env env) {
	int cols = sqlite3_column_count(stmt_);
	Napi::Array arr = Napi::Array::New(env, cols);
	for (int c = 0; c < cols; c++) {
		arr.Set(static_cast<uint32_t>(c), ColumnToJS(env, c));
	}
	return arr;
}

Napi::Value StatementWrapper::Run(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (finalized_) {
		Napi::TypeError::New(env, "This statement has been finalized").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	BindParams(env, info);
	if (env.IsExceptionPending()) return env.Undefined();

	int rc = sqlite3_step(stmt_);
	if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
		sqlite3_reset(stmt_);
		db_->ThrowSqliteError(env, rc);
		return env.Undefined();
	}

	Napi::Object result = Napi::Object::New(env);
	result.Set("changes", Napi::Number::New(env, static_cast<double>(sqlite3_changes(db_->GetHandle()))));
	int64_t lastId = sqlite3_last_insert_rowid(db_->GetHandle());
	if (safeIntegers_) {
		result.Set("lastInsertRowid", Napi::BigInt::New(env, lastId));
	} else {
		result.Set("lastInsertRowid", Napi::Number::New(env, static_cast<double>(lastId)));
	}

	sqlite3_reset(stmt_);
	return result;
}

Napi::Value StatementWrapper::Get(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (finalized_) {
		Napi::TypeError::New(env, "This statement has been finalized").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	BindParams(env, info);
	if (env.IsExceptionPending()) return env.Undefined();

	int rc = sqlite3_step(stmt_);
	if (rc == SQLITE_ROW) {
		Napi::Value result = rawMode_
			? static_cast<Napi::Value>(RowToArray(env))
			: static_cast<Napi::Value>(RowToObject(env));
		sqlite3_reset(stmt_);
		return result;
	}

	sqlite3_reset(stmt_);
	if (rc == SQLITE_DONE) {
		return env.Undefined();
	}

	db_->ThrowSqliteError(env, rc);
	return env.Undefined();
}

Napi::Value StatementWrapper::All(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (finalized_) {
		Napi::TypeError::New(env, "This statement has been finalized").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	BindParams(env, info);
	if (env.IsExceptionPending()) return env.Undefined();

	Napi::Array rows = Napi::Array::New(env);
	uint32_t idx = 0;
	int rc;
	while ((rc = sqlite3_step(stmt_)) == SQLITE_ROW) {
		if (rawMode_) {
			rows.Set(idx++, RowToArray(env));
		} else {
			rows.Set(idx++, RowToObject(env));
		}
	}

	sqlite3_reset(stmt_);
	if (rc != SQLITE_DONE) {
		db_->ThrowSqliteError(env, rc);
		return env.Undefined();
	}

	return rows;
}

Napi::Value StatementWrapper::Iterate(const Napi::CallbackInfo& info) {
	// For simplicity, iterate returns the same as all() in this implementation.
	// A full iterator protocol would require a custom JS iterator object.
	return All(info);
}

Napi::Value StatementWrapper::Columns(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (finalized_) {
		Napi::TypeError::New(env, "This statement has been finalized").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	int cols = sqlite3_column_count(stmt_);
	Napi::Array result = Napi::Array::New(env, cols);
	for (int c = 0; c < cols; c++) {
		Napi::Object col = Napi::Object::New(env);
		const char* colNameRaw = sqlite3_column_name(stmt_, c);
		col.Set("name", Napi::String::New(env, colNameRaw ? colNameRaw : ""));

		const char* dbName = sqlite3_column_database_name(stmt_, c);
		const char* tableName = sqlite3_column_table_name(stmt_, c);
		const char* originName = sqlite3_column_origin_name(stmt_, c);
		const char* declType = sqlite3_column_decltype(stmt_, c);

		col.Set("column", originName ? Napi::String::New(env, originName) : env.Null());
		col.Set("table", tableName ? Napi::String::New(env, tableName) : env.Null());
		col.Set("database", dbName ? Napi::String::New(env, dbName) : env.Null());
		col.Set("type", declType ? Napi::String::New(env, declType) : env.Null());

		result.Set(static_cast<uint32_t>(c), col);
	}
	return result;
}

Napi::Value StatementWrapper::Bind(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	BindParams(env, info);
	return info.This();
}

Napi::Value StatementWrapper::SafeIntegers(const Napi::CallbackInfo& info) {
	if (info.Length() >= 1 && info[0].IsBoolean()) {
		safeIntegers_ = info[0].As<Napi::Boolean>().Value();
	} else {
		safeIntegers_ = true;
	}
	return info.This();
}

Napi::Value StatementWrapper::Raw(const Napi::CallbackInfo& info) {
	if (info.Length() >= 1 && info[0].IsBoolean()) {
		rawMode_ = info[0].As<Napi::Boolean>().Value();
	} else {
		rawMode_ = true;
	}
	return info.This();
}

Napi::Value StatementWrapper::Expand(const Napi::CallbackInfo& info) {
	if (info.Length() >= 1 && info[0].IsBoolean()) {
		expandMode_ = info[0].As<Napi::Boolean>().Value();
	} else {
		expandMode_ = true;
	}
	return info.This();
}

// Property getters
Napi::Value StatementWrapper::GetSource(const Napi::CallbackInfo& info) {
	return Napi::String::New(info.Env(), source_);
}
Napi::Value StatementWrapper::GetReader(const Napi::CallbackInfo& info) {
	if (!stmt_) return Napi::Boolean::New(info.Env(), false);
	return Napi::Boolean::New(info.Env(), sqlite3_column_count(stmt_) > 0);
}
Napi::Value StatementWrapper::GetBusy(const Napi::CallbackInfo& info) {
	if (!stmt_) return Napi::Boolean::New(info.Env(), false);
	return Napi::Boolean::New(info.Env(), sqlite3_stmt_busy(stmt_) != 0);
}
