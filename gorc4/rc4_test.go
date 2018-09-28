/*
	rc4_test.go

	RFC6229, Test Vectors for the Stream Cipher RC4
	See: https://tools.ietf.org/html/rfc6229

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	rc4_test.go Daniel Havir, 2018
*/

package main

import (
	"bytes"
	"testing"
)

type testpair struct {
	offset uint16
	result string
}

var plain = make([]byte, 16)

func testrun(t *testing.T, key []byte, testpairs []testpair) {
	for _, pair := range testpairs {
		rc4 := KSA(key)
		if pair.offset > 0 {
			rc4.PRGA(make([]byte, pair.offset))
		}
		encrypted := rc4.PRGA(plain)
		expected := decodehex([]byte(pair.result))
		if !(bytes.Equal(encrypted, expected)) {
			t.Error("Expected ", string(encodehex(expected)),
				",got ", string(encodehex(encrypted)))
		}
	}
}

func Test40BitsKey1(t *testing.T) {
	keyHex := []byte("0102030405")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "b2396305f03dc027ccc3524a0a1118a8"},
		{16, "6982944f18fc82d589c403a47a0d0919"},
		{240, "28cb1132c96ce286421dcaadb8b69eae"},
		{256, "1cfcf62b03eddb641d77dfcf7f8d8c93"},
		{496, "42b7d0cdd918a8a33dd51781c81f4041"},
		{512, "6459844432a7da923cfb3eb4980661f6"},
		{752, "ec10327bde2beefd18f9277680457e22"},
		{768, "eb62638d4f0ba1fe9fca20e05bf8ff2b"},
		{1008, "45129048e6a0ed0b56b490338f078da5"},
		{1024, "30abbcc7c20b01609f23ee2d5f6bb7df"},
		{1520, "3294f744d8f9790507e70f62e5bbceea"},
		{1536, "d8729db41882259bee4f825325f5a130"},
		{2032, "1eb14a0c13b3bf47fa2a0ba93ad45b8b"},
		{2048, "cc582f8ba9f265e2b1be9112e975d2d7"},
		{3056, "f2e30f9bd102ecbf75aaade9bc35c43c"},
		{3072, "ec0e11c479dc329dc8da7968fe965681"},
		{4080, "068326a2118416d21f9d04b2cd1ca050"},
		{4096, "ff25b58995996707e51fbdf08b34d875"},
	}

	testrun(t, key, testpairs)
}

func Test56BitsKey1(t *testing.T) {
	keyHex := []byte("01020304050607")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "293f02d47f37c9b633f2af5285feb46b"},
		{16, "e620f1390d19bd84e2e0fd752031afc1"},
		{240, "914f02531c9218810df60f67e338154c"},
		{256, "d0fdb583073ce85ab83917740ec011d5"},
		{496, "75f81411e871cffa70b90c74c592e454"},
		{512, "0bb87202938dad609e87a5a1b079e5e4"},
		{752, "c2911246b612e7e7b903dfeda1dad866"},
		{768, "32828f91502b6291368de8081de36fc2"},
		{1008, "f3b9a7e3b297bf9ad804512f9063eff1"},
		{1024, "8ecb67a9ba1f55a5a067e2b026a3676f"},
		{1520, "d2aa902bd42d0d7cfd340cd45810529f"},
		{1536, "78b272c96e42eab4c60bd914e39d06e3"},
		{2032, "f4332fd31a079396ee3cee3f2a4ff049"},
		{2048, "05459781d41fda7f30c1be7e1246c623"},
		{3056, "adfd3868b8e51485d5e610017e3dd609"},
		{3072, "ad26581c0c5be45f4cea01db2f3805d5"},
		{4080, "f3172ceffc3b3d997c85ccd5af1a950c"},
		{4096, "e74b0b9731227fd37c0ec08a47ddd8b8"},
	}

	testrun(t, key, testpairs)
}

func Test64BitsKey1(t *testing.T) {
	keyHex := []byte("0102030405060708")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "97ab8a1bf0afb96132f2f67258da15a8"},
		{16, "8263efdb45c4a18684ef87e6b19e5b09"},
		{240, "9636ebc9841926f4f7d1f362bddf6e18"},
		{256, "d0a990ff2c05fef5b90373c9ff4b870a"},
		{496, "73239f1db7f41d80b643c0c52518ec63"},
		{512, "163b319923a6bdb4527c626126703c0f"},
		{752, "49d6c8af0f97144a87df21d91472f966"},
		{768, "44173a103b6616c5d5ad1cee40c863d0"},
		{1008, "273c9c4b27f322e4e716ef53a47de7a4"},
		{1024, "c6d0e7b226259fa9023490b26167ad1d"},
		{1520, "1fe8986713f07c3d9ae1c163ff8cf9d3"},
		{1536, "8369e1a965610be887fbd0c79162aafb"},
		{2032, "0a0127abb44484b9fbef5abcae1b579f"},
		{2048, "c2cdadc6402e8ee866e1f37bdb47e42c"},
		{3056, "26b51ea37df8e1d6f76fc3b66a7429b3"},
		{3072, "bc7683205d4f443dc1f29dda3315c87b"},
		{4080, "d5fa5a3469d29aaaf83d23589db8c85b"},
		{4096, "3fb46e2c8f0f068edce8cdcd7dfc5862"},
	}

	testrun(t, key, testpairs)
}

func Test80BitsKey1(t *testing.T) {
	keyHex := []byte("0102030405060708090a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "ede3b04643e586cc907dc21851709902"},
		{16, "03516ba78f413beb223aa5d4d2df6711"},
		{240, "3cfd6cb58ee0fdde640176ad0000044d"},
		{256, "48532b21fb6079c9114c0ffd9c04a1ad"},
		{496, "3e8cea98017109979084b1ef92f99d86"},
		{512, "e20fb49bdb337ee48b8d8dc0f4afeffe"},
		{752, "5c2521eacd7966f15e056544bea0d315"},
		{768, "e067a7031931a246a6c3875d2f678acb"},
		{1008, "a64f70af88ae56b6f87581c0e23e6b08"},
		{1024, "f449031de312814ec6f319291f4a0516"},
		{1520, "bdae85924b3cb1d0a2e33a30c6d79599"},
		{1536, "8a0feddbac865a09bcd127fb562ed60a"},
		{2032, "b55a0a5b51a12a8be34899c3e047511a"},
		{2048, "d9a09cea3ce75fe39698070317a71339"},
		{3056, "552225ed1177f44584ac8cfa6c4eb5fc"},
		{3072, "7e82cbabfc95381b080998442129c2f8"},
		{4080, "1f135ed14ce60a91369d2322bef25e3c"},
		{4096, "08b6be45124a43e2eb77953f84dc8553"},
	}

	testrun(t, key, testpairs)
}

func Test128BitsKey1(t *testing.T) {
	keyHex := []byte("0102030405060708090a0b0c0d0e0f10")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "9ac7cc9a609d1ef7b2932899cde41b97"},
		{16, "5248c4959014126a6e8a84f11d1a9e1c"},
		{240, "065902e4b620f6cc36c8589f66432f2b"},
		{256, "d39d566bc6bce3010768151549f3873f"},
		{496, "b6d1e6c4a5e4771cad79538df295fb11"},
		{512, "c68c1d5c559a974123df1dbc52a43b89"},
		{752, "c5ecf88de897fd57fed301701b82a259"},
		{768, "eccbe13de1fcc91c11a0b26c0bc8fa4d"},
		{1008, "e7a72574f8782ae26aabcf9ebcd66065"},
		{1024, "bdf0324e6083dcc6d3cedd3ca8c53c16"},
		{1520, "b40110c4190b5622a96116b0017ed297"},
		{1536, "ffa0b514647ec04f6306b892ae661181"},
		{2032, "d03d1bc03cd33d70dff9fa5d71963ebd"},
		{2048, "8a44126411eaa78bd51e8d87a8879bf5"},
		{3056, "fabeb76028ade2d0e48722e46c4615a3"},
		{3072, "c05d88abd50357f935a63c59ee537623"},
		{4080, "ff38265c1642c1abe8d3c2fe5e572bf8"},
		{4096, "a36a4c301ae8ac13610ccbc12256cacc"},
	}

	testrun(t, key, testpairs)
}

func Test192BitsKey1(t *testing.T) {
	keyHex := []byte("0102030405060708090a0b0c0d0e0f101112131415161718")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "0595e57fe5f0bb3c706edac8a4b2db11"},
		{16, "dfde31344a1af769c74f070aee9e2326"},
		{240, "b06b9b1e195d13d8f4a7995c4553ac05"},
		{256, "6bd2378ec341c9a42f37ba79f88a32ff"},
		{496, "e70bce1df7645adb5d2c4130215c3522"},
		{512, "9a5730c7fcb4c9af51ffda89c7f1ad22"},
		{752, "0485055fd4f6f0d963ef5ab9a5476982"},
		{768, "591fc66bcda10e452b03d4551f6b62ac"},
		{1008, "2753cc83988afa3e1688a1d3b42c9a02"},
		{1024, "93610d523d1d3f0062b3c2a3bbc7c7f0"},
		{1520, "96c248610aadedfeaf8978c03de8205a"},
		{1536, "0e317b3d1c73b9e9a4688f296d133a19"},
		{2032, "bdf0e6c3cca5b5b9d533b69c56ada120"},
		{2048, "88a218b6e2ece1e6246d44c759d19b10"},
		{3056, "6866397e95c140534f94263421006e40"},
		{3072, "32cb0a1e9542c6b3b8b398abc3b0f1d5"},
		{4080, "29a0b8aed54a132324c62e423f54b4c8"},
		{4096, "3cb0f3b5020a98b82af9fe154484a168"},
	}

	testrun(t, key, testpairs)
}

func Test256BitsKey1(t *testing.T) {
	keyHex := []byte("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "eaa6bd25880bf93d3f5d1e4ca2611d91"},
		{16, "cfa45c9f7e714b54bdfa80027cb14380"},
		{240, "114ae344ded71b35f2e60febad727fd8"},
		{256, "02e1e7056b0f623900496422943e97b6"},
		{496, "91cb93c787964e10d9527d999c6f936b"},
		{512, "49b18b42f8e8367cbeb5ef104ba1c7cd"},
		{752, "87084b3ba700bade955610672745b374"},
		{768, "e7a7b9e9ec540d5ff43bdb12792d1b35"},
		{1008, "c799b596738f6b018c76c74b1759bd90"},
		{1024, "7fec5bfd9f9b89ce6548309092d7e958"},
		{1520, "40f250b26d1f096a4afd4c340a588815"},
		{1536, "3e34135c79db010200767651cf263073"},
		{2032, "f656abccf88dd827027b2ce917d464ec"},
		{2048, "18b62503bfbc077fbabb98f20d98ab34"},
		{3056, "8aed95ee5b0dcbfbef4eb21d3a3f52f9"},
		{3072, "625a1ab00ee39a5327346bddb01a9c18"},
		{4080, "a13a7c79c7e119b5ab0296ab28c300b9"},
		{4096, "f3e4c0a2e02d1d01f7f0a74618af2b48"},
	}

	testrun(t, key, testpairs)
}

func Test40BitsKey2(t *testing.T) {
	keyHex := []byte("833222772a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "80ad97bdc973df8a2e879e92a497efda"},
		{16, "20f060c2f2e5126501d3d4fea10d5fc0"},
		{240, "faa148e99046181fec6b2085f3b20ed9"},
		{256, "f0daf5bab3d596839857846f73fbfe5a"},
		{496, "1c7e2fc4639232fe297584b296996bc8"},
		{512, "3db9b249406cc8edffac55ccd322ba12"},
		{752, "e4f9f7e0066154bbd125b745569bc897"},
		{768, "75d5ef262b44c41a9cf63ae14568e1b9"},
		{1008, "6da453dbf81e82334a3d8866cb50a1e3"},
		{1024, "7828d074119cab5c22b294d7a9bfa0bb"},
		{1520, "adb89cea9a15fbe617295bd04b8ca05c"},
		{1536, "6251d87fd4aaae9a7e4ad5c217d3f300"},
		{2032, "e7119bd6dd9b22afe8f89585432881e2"},
		{2048, "785b60fd7ec4e9fcb6545f350d660fab"},
		{3056, "afecc037fdb7b0838eb3d70bcd268382"},
		{3072, "dbc1a7b49d57358cc9fa6d61d73b7cf0"},
		{4080, "6349d126a37afcba89794f9804914fdc"},
		{4096, "bf42c3018c2f7c66bfde524975768115"},
	}

	testrun(t, key, testpairs)
}

func Test56BitsKey2(t *testing.T) {
	keyHex := []byte("1910833222772a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "bc9222dbd3274d8fc66d14ccbda6690b"},
		{16, "7ae627410c9a2be693df5bb7485a63e3"},
		{240, "3f0931aa03defb300f060103826f2a64"},
		{256, "beaa9ec8d59bb68129f3027c96361181"},
		{496, "74e04db46d28648d7dee8a0064b06cfe"},
		{512, "9b5e81c62fe023c55be42f87bbf932b8"},
		{752, "ce178fc1826efecbc182f57999a46140"},
		{768, "8bdf55cd55061c06dba6be11de4a578a"},
		{1008, "626f5f4dce652501f3087d39c92cc349"},
		{1024, "42daac6a8f9ab9a7fd137c6037825682"},
		{1520, "cc03fdb79192a207312f53f5d4dc33d9"},
		{1536, "f70f14122a1c98a3155d28b8a0a8a41d"},
		{2032, "2a3a307ab2708a9c00fe0b42f9c2d6a1"},
		{2048, "862617627d2261eab0b1246597ca0ae9"},
		{3056, "55f877ce4f2e1ddbbf8e13e2cde0fdc8"},
		{3072, "1b1556cb935f173337705fbb5d501fc1"},
		{4080, "ecd0e96602be7f8d5092816cccf2c2e9"},
		{4096, "027881fab4993a1c262024a94fff3f61"},
	}

	testrun(t, key, testpairs)
}

func Test64BitsKey2(t *testing.T) {
	keyHex := []byte("641910833222772a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "bbf609de9413172d07660cb680716926"},
		{16, "46101a6dab43115d6c522b4fe93604a9"},
		{240, "cbe1fff21c96f3eef61e8fe0542cbdf0"},
		{256, "347938bffa4009c512cfb4034b0dd1a7"},
		{496, "7867a786d00a7147904d76ddf1e520e3"},
		{512, "8d3e9e1caefcccb3fbf8d18f64120b32"},
		{752, "942337f8fd76f0fae8c52d7954810672"},
		{768, "b8548c10f51667f6e60e182fa19b30f7"},
		{1008, "0211c7c6190c9efd1237c34c8f2e06c4"},
		{1024, "bda64f65276d2aacb8f90212203a808e"},
		{1520, "bd3820f732ffb53ec193e79d33e27c73"},
		{1536, "d0168616861907d482e36cdac8cf5749"},
		{2032, "97b0f0f224b2d2317114808fb03af7a0"},
		{2048, "e59616e469787939a063ceea9af956d1"},
		{3056, "c47e0dc1660919c11101208f9e69aa1f"},
		{3072, "5ae4f12896b8379a2aad89b5b553d6b0"},
		{4080, "6b6b098d0c293bc2993d80bf0518b6d9"},
		{4096, "8170cc3ccd92a698621b939dd38fe7b9"},
	}

	testrun(t, key, testpairs)
}

func Test80BitsKey2(t *testing.T) {
	keyHex := []byte("8b37641910833222772a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "ab65c26eddb287600db2fda10d1e605c"},
		{16, "bb759010c29658f2c72d93a2d16d2930"},
		{240, "b901e8036ed1c383cd3c4c4dd0a6ab05"},
		{256, "3d25ce4922924c55f064943353d78a6c"},
		{496, "12c1aa44bbf87e75e611f69b2c38f49b"},
		{512, "28f2b3434b65c09877470044c6ea170d"},
		{752, "bd9ef822de5288196134cf8af7839304"},
		{768, "67559c23f052158470a296f725735a32"},
		{1008, "8bab26fbc2c12b0f13e2ab185eabf241"},
		{1024, "31185a6d696f0cfa9b42808b38e132a2"},
		{1520, "564d3dae183c5234c8af1e51061c44b5"},
		{1536, "3c0778a7b5f72d3c23a3135c7d67b9f4"},
		{2032, "f34369890fcf16fb517dcaae4463b2dd"},
		{2048, "02f31c81e8200731b899b028e791bfa7"},
		{3056, "72da646283228c14300853701795616f"},
		{3072, "4e0a8c6f7934a788e2265e81d6d0c8f4"},
		{4080, "438dd5eafea0111b6f36b4b938da2a68"},
		{4096, "5f6bfc73815874d97100f086979357d8"},
	}

	testrun(t, key, testpairs)
}

func Test128BitsKey2(t *testing.T) {
	keyHex := []byte("ebb46227c6cc8b37641910833222772a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "720c94b63edf44e131d950ca211a5a30"},
		{16, "c366fdeacf9ca80436be7c358424d20b"},
		{240, "b3394a40aabf75cba42282ef25a0059f"},
		{256, "4847d81da4942dbc249defc48c922b9f"},
		{496, "08128c469f275342adda202b2b58da95"},
		{512, "970dacef40ad98723bac5d6955b81761"},
		{752, "3cb89993b07b0ced93de13d2a11013ac"},
		{768, "ef2d676f1545c2c13dc680a02f4adbfe"},
		{1008, "b60595514f24bc9fe522a6cad7393644"},
		{1024, "b515a8c5011754f59003058bdb81514e"},
		{1520, "3c70047e8cbc038e3b9820db601da495"},
		{1536, "1175da6ee756de46a53e2b075660b770"},
		{2032, "00a542bba02111cc2c65b38ebdba587e"},
		{2048, "5865fdbb5b48064104e830b380f2aede"},
		{3056, "34b21ad2ad44e999db2d7f0863f0d9b6"},
		{3072, "84a9218fc36e8a5f2ccfbeae53a27d25"},
		{4080, "a2221a11b833ccb498a59540f0545f4a"},
		{4096, "5bbeb4787d59e5373fdbea6c6f75c29b"},
	}

	testrun(t, key, testpairs)
}

func Test192BitsKey2(t *testing.T) {
	keyHex := []byte("c109163908ebe51debb46227c6cc8b37641910833222772a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "54b64e6b5a20b5e2ec84593dc7989da7"},
		{16, "c135eee237a85465ff97dc03924f45ce"},
		{240, "cfcc922fb4a14ab45d6175aabbf2d201"},
		{256, "837b87e2a446ad0ef798acd02b94124f"},
		{496, "17a6dbd664926a0636b3f4c37a4f4694"},
		{512, "4a5f9f26aeeed4d4a25f632d305233d9"},
		{752, "80a3d01ef00c8e9a4209c17f4eeb358c"},
		{768, "d15e7d5ffaaabc0207bf200a117793a2"},
		{1008, "349682bf588eaa52d0aa1560346aeafa"},
		{1024, "f5854cdb76c889e3ad63354e5f7275e3"},
		{1520, "532c7ceccb39df3236318405a4b1279c"},
		{1536, "baefe6d9ceb651842260e0d1e05e3b90"},
		{2032, "e82d8c6db54e3c633f581c952ba04207"},
		{2048, "4b16e50abd381bd70900a9cd9a62cb23"},
		{3056, "3682ee33bd148bd9f58656cd8f30d9fb"},
		{3072, "1e5a0b8475045d9b20b2628624edfd9e"},
		{4080, "63edd684fb826282fe528f9c0e9237bc"},
		{4096, "e4dd2e98d6960fae0b43545456743391"},
	}

	testrun(t, key, testpairs)
}

func Test256BitsKey2(t *testing.T) {
	keyHex := []byte("1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a")
	key := decodehex(keyHex)

	testpairs := []testpair{
		{0, "dd5bcb0018e922d494759d7c395d02d3"},
		{16, "c8446f8f77abf737685353eb89a1c9eb"},
		{240, "af3e30f9c095045938151575c3fb9098"},
		{256, "f8cb6274db99b80b1d2012a98ed48f0e"},
		{496, "25c3005a1cb85de076259839ab7198ab"},
		{512, "9dcbc183e8cb994b727b75be3180769c"},
		{752, "a1d3078dfa9169503ed9d4491dee4eb2"},
		{768, "8514a5495858096f596e4bcd66b10665"},
		{1008, "5f40d59ec1b03b33738efa60b2255d31"},
		{1024, "3477c7f764a41baceff90bf14f92b7cc"},
		{1520, "ac4e95368d99b9eb78b8da8f81ffa795"},
		{1536, "8c3c13f8c2388bb73f38576e65b7c446"},
		{2032, "13c4b9c1dfb66579eddd8a280b9f7316"},
		{2048, "ddd27820550126698efaadc64b64f66e"},
		{3056, "f08f2e66d28ed143f3a237cf9de73559"},
		{3072, "9ea36c525531b880ba124334f57b0b70"},
		{4080, "d5a39e3dfcc50280bac4a6b5aa0dca7d"},
		{4096, "370b1c1fe655916d97fd0d47ca1d72b8"},
	}

	testrun(t, key, testpairs)
}
