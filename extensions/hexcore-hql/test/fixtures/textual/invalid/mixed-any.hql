hql 1.0;
rule "invalid.mixed_any" {
  name "Invalid";
  description "Mixed any cannot lower to HQL 0.4.0.";
  severity info;
  where any {
    ast CCallExpr {
    };
    fact summary-call {
    };
  }
}
