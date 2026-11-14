hql 1.0;
rule "invalid.fact" {
  name "Invalid";
  description "Invalid fact.";
  severity info;
  where fact summary-ownershp {
  }
}
