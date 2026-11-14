hql 1.0;
rule "invalid.node" {
  name "Invalid";
  description "Invalid node.";
  severity info;
  where ast CStringLiteral {
  }
}
