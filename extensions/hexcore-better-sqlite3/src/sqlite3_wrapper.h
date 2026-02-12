/*
 * HexCore SQLite3 - Native Node.js Bindings
 * SQLite3 Wrapper Header
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#ifndef SQLITE3_WRAPPER_H
#define SQLITE3_WRAPPER_H

#include <napi.h>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <unordered_set>

// Forward declarations
class StatementWrapper;

/**
 * DatabaseWrapper - N-API class wrapping SQLite3 database connection
 *
 * JavaScript usage:
 *   const db = new addon.Database(':memory:');
 *   db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)');
 *   const stmt = db.prepare('INSERT INTO t(val) VALUES (?)');
 *   stmt.run('hello');
 *   db.close();
 */
class DatabaseWrapper : public Napi::ObjectWrap<DatabaseWrapper> {
public:
	static Napi::Object Init(Napi::Env env, Napi::Object exports);
	DatabaseWrapper(const Napi::CallbackInfo& info);
	~DatabaseWrapper();

	sqlite3* GetHandle() const { return db_; }
	bool IsOpened() const { return db_ != nullptr; }
	void TrackStatement(StatementWrapper* stmt);
	void UntrackStatement(StatementWrapper* stmt);

private:
	sqlite3* db_;
	bool open_;
	bool readonly_;
	bool memory_;
	std::string name_;
	std::unordered_set<StatementWrapper*> statements_;

	static Napi::FunctionReference constructor;

	// Methods exposed to JS
	Napi::Value Prepare(const Napi::CallbackInfo& info);
	Napi::Value Exec(const Napi::CallbackInfo& info);
	Napi::Value Close(const Napi::CallbackInfo& info);
	Napi::Value Pragma(const Napi::CallbackInfo& info);
	Napi::Value LoadExtension(const Napi::CallbackInfo& info);
	Napi::Value DefaultSafeIntegers(const Napi::CallbackInfo& info);

	// Property getters
	Napi::Value GetName(const Napi::CallbackInfo& info);
	Napi::Value GetOpen(const Napi::CallbackInfo& info);
	Napi::Value GetInTransaction(const Napi::CallbackInfo& info);
	Napi::Value GetReadonly(const Napi::CallbackInfo& info);
	Napi::Value GetMemory(const Napi::CallbackInfo& info);

	bool safeIntegers_;

	void ThrowSqliteError(Napi::Env env);
	void ThrowSqliteError(Napi::Env env, int rc);

	friend class StatementWrapper;
};

/**
 * StatementWrapper - N-API class wrapping SQLite3 prepared statement
 */
class StatementWrapper : public Napi::ObjectWrap<StatementWrapper> {
public:
	static Napi::Object Init(Napi::Env env, Napi::Object exports);
	StatementWrapper(const Napi::CallbackInfo& info);
	~StatementWrapper();

	void Finalize(Napi::Env env);
	void FinalizeStatement();

private:
	sqlite3_stmt* stmt_;
	DatabaseWrapper* db_;
	bool finalized_;
	std::string source_;
	bool safeIntegers_;
	bool rawMode_;
	bool expandMode_;

	static Napi::FunctionReference constructor;
	friend class DatabaseWrapper;

	// Methods exposed to JS
	Napi::Value Run(const Napi::CallbackInfo& info);
	Napi::Value Get(const Napi::CallbackInfo& info);
	Napi::Value All(const Napi::CallbackInfo& info);
	Napi::Value Iterate(const Napi::CallbackInfo& info);
	Napi::Value Columns(const Napi::CallbackInfo& info);
	Napi::Value Bind(const Napi::CallbackInfo& info);
	Napi::Value SafeIntegers(const Napi::CallbackInfo& info);
	Napi::Value Raw(const Napi::CallbackInfo& info);
	Napi::Value Expand(const Napi::CallbackInfo& info);

	// Property getters
	Napi::Value GetSource(const Napi::CallbackInfo& info);
	Napi::Value GetReader(const Napi::CallbackInfo& info);
	Napi::Value GetBusy(const Napi::CallbackInfo& info);

	// Helpers
	void BindParams(Napi::Env env, const Napi::CallbackInfo& info, int startIdx = 0);
	void BindValue(Napi::Env env, int index, Napi::Value val);
	Napi::Value ColumnToJS(Napi::Env env, int col);
	Napi::Object RowToObject(Napi::Env env);
	Napi::Array RowToArray(Napi::Env env);
};

#endif // SQLITE3_WRAPPER_H
