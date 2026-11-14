hql 2.0;
rule "invalid.version" {
  name "Invalid";
  description "Invalid version.";
  severity info;
  where ast CCallExpr {
  }
}
