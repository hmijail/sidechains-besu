/*
 * Copyright 2018 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.hyperledger.besu.consensus.ibft;

import org.hyperledger.besu.consensus.common.VoteProposer;
import org.hyperledger.besu.consensus.common.VoteTallyCache;
import org.hyperledger.besu.crosschain.core.CrosschainController;

/** Holds the IBFT specific mutable state. */
public class IbftContext {

  private final VoteTallyCache voteTallyCache;
  private final VoteProposer voteProposer;
  private final CrosschainController crosschainController;

  public IbftContext(
      final VoteTallyCache voteTallyCache,
      final VoteProposer voteProposer,
      final CrosschainController crosschainController) {
    this.voteTallyCache = voteTallyCache;
    this.voteProposer = voteProposer;
    this.crosschainController = crosschainController;
  }

  public VoteTallyCache getVoteTallyCache() {
    return voteTallyCache;
  }

  public VoteProposer getVoteProposer() {
    return voteProposer;
  }

  public CrosschainController getCrosschainController() {
    return crosschainController;
  }
}
