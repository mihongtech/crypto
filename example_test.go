// Copyright 2017 Tendermint. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto_test

import (
	"fmt"

	"github.com/mihongtech/crypto"
)

func ExampleSha256() {
	sum := crypto.Sha256([]byte("This is Tendermint"))
	fmt.Printf("%x\n", sum)
	// Output:
	// ab617a03d0a63c838b4dfbb2732e95088c66308b4fff74b231471fdba23a338f
}
