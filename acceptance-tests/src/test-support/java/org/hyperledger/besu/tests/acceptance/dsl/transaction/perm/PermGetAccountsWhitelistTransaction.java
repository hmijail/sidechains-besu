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
package org.hyperledger.besu.tests.acceptance.dsl.transaction.perm;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.tests.acceptance.dsl.transaction.NodeRequests;
import org.hyperledger.besu.tests.acceptance.dsl.transaction.Transaction;
import org.hyperledger.besu.tests.acceptance.dsl.transaction.perm.PermissioningJsonRpcRequestFactory.GetAccountsWhitelistResponse;

import java.io.IOException;
import java.util.List;

public class PermGetAccountsWhitelistTransaction implements Transaction<List<String>> {

  @Override
  public List<String> execute(final NodeRequests node) {
    try {
      GetAccountsWhitelistResponse response = node.perm().getAccountsWhitelist().send();
      assertThat(response.getResult()).isNotNull();
      return response.getResult();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
