hql 1.0;

rule "memory.allocator_candidate" {
  version "1.0.0";
  namespace "memory";
  status nursery;
  author "AkashaCorporation";
  license "MIT";
  provenance {
    kind internal;
    source "G05 textual HQL fixture";
    modified false;
  }
  compatibility {
    hql ">=0.3.1 <1.0.0";
    helix ">=0.9.4";
    hast 1;
  }
  fixtures "textual/v1/memory-allocator.hql.json";
  limitations ["Function-scoped candidate; no path proof."];
  supersedes ["memory.allocator_candidate.legacy"];
  name "Allocator candidate";
  description "Matches allocator structure and typed ownership evidence.";
  severity info;
  mitre ["T1105"];
  evidence candidate;
  calibration {
    confidence 0.75;
    corpus "g05-textual-fixture";
    sha256 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  }
  where all {
    ast CCallExpr {
      callee == /^(malloc|calloc)$/;
      operand 0 ast CVarRefExpr {
        type == "size_t";
      };
      contains ast CCastExpr {
        targetType == "void *";
      };
      minDepth 0;
      maxDepth 4;
    };
    any {
      ast CForStmt {
      };
      not ast CWhileStmt {
      };
    };
    count min 1 max 3 ast CFieldAccessExpr {
      arrow == true;
    };
    fact summary-ownership {
      ownershipKind == "allocate";
    };
    not fact summary-barrier {
      lossy == true;
    };
    count exactly 1 fact summary-call {
      calleeIdentity == /malloc$/;
    };
  }
}
