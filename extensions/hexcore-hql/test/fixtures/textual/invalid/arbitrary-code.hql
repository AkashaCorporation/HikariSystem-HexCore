hql 1.0;
rule "invalid.script" {
  name "Invalid";
  description "Script execution is forbidden.";
  severity info;
  where ast CCallExpr {
    callee == `${process.execPath}`;
  }
}
