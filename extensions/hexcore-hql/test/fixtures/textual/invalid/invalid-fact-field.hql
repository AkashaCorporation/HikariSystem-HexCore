hql 1.0;
rule "invalid.fact_field" {
  name "Invalid";
  description "Invalid fact field.";
  severity info;
  where fact summary-ownership {
    ownershipKinds == "allocate";
  }
}
