// JSON as returned by /validators?height=<H>
export interface ValidatorResponse {
  jsonrpc: string;
  id: number;
  result: {
    block_height: string;
    validators: {
      address: string;
      pub_key: {
        type: string;
        value: string;
      };
      voting_power: string;
      proposer_priority: string;
    }[];
    count: string;
    total: string;
  };
}

// JSON as returned by /commit?height=<H>
export interface CommitResponse {
  jsonrpc: string;
  id: number;
  result: {
    signed_header: {
      header: {
        version: {
          block: string;
          app: string;
        };
        chain_id: string;
        height: string;
        time: string; // RFC3339 timestamp
        last_block_id: {
          hash: string;
          parts: {
            total: number;
            hash: string;
          };
        };
        last_commit_hash: string;
        data_hash: string;
        validators_hash: string;
        next_validators_hash: string;
        consensus_hash: string;
        app_hash: string;
        last_results_hash: string;
        evidence_hash: string;
        proposer_address: string;
      };
      commit: {
        height: string;
        round: number;
        block_id: {
          hash: string;
          parts: {
            total: number;
            hash: string;
          };
        };
        signatures: {
          block_id_flag: number;
          validator_address: string;
          timestamp: string;
          signature: string; // base64
        }[];
      };
    };
    canonical: boolean;
  };
}
