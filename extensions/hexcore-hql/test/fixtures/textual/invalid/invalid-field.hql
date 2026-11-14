hql 1.0;
rule "invalid.field" {
  name "Invalid";
  description "Invalid field.";
  severity info;
  where ast CCallExpr {
    calleee == "VirtualAlloc";
  }
}
