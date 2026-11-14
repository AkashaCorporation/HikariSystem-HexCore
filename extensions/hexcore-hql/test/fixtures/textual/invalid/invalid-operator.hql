hql 1.0;
rule "invalid.operator" {
  name "Invalid";
  description "Invalid operator.";
  severity info;
  where ast CBinaryExpr {
    operator == "ROTATE_MAGIC";
  }
}
