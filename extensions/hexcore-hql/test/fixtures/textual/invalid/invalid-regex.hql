hql 1.0;
rule "invalid.regex" {
  name "Invalid";
  description "Invalid regex.";
  severity info;
  where ast CCallExpr {
    callee == /[unterminated/;
  }
}
