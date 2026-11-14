hql 1.0;
rule "invalid.mixed_any" {
  name "Invalid";
  description "Mixed any cannot lower to HQL 0.3.1.";
  severity info;
  where any {
    ast CCallExpr {
    };
    fact summary-call {
    };
  }
}
