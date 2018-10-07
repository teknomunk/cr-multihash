require "./spec_helper"

SAMPLE_TEXT = "Merkle–Damgård"

describe MultiHash do
  # TODO: Write tests

  describe "#encode_sha1" do
	  it "works" do
	  	MultiHash.encode_sha1(SAMPLE_TEXT).should eq(
			"11148a173fd3e32c0fa78b90fe42d305f202244e2739".to_slice_from_hexstring
			)
	  end
  end
  describe "#encode_sha2_256" do
	  it "works" do
	  	MultiHash.encode_sha2_256(SAMPLE_TEXT).should eq(
			"122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8".to_slice_from_hexstring
			)
	  end
  end
  describe "#encode_sha2_512" do
	  it "works" do
	  	MultiHash.encode_sha2_512(SAMPLE_TEXT).should eq(
			("134052eb4dd19f1ec522859e12d89706156570f8fbab1824870bc6f8c7d235eef5f4c"+
			 "2cbbafd365f96fb12b1d98a0334870c2ce90355da25e6a1108a6e17c4aaebb0").to_slice_from_hexstring
			)
	  end
  end
  describe "#decode" do
  	it "Decodes sha1 hashes" do
		io = IO::Memory.new("11148a173fd3e32c0fa78b90fe42d305f202244e2739".to_slice_from_hexstring)
		MultiHash.decode( io ).should eq( {"sha1",20_u64,MultiHash.digest_sha1(SAMPLE_TEXT)} )
	end
	it "Decodes sha2-256 hashes" do
		io = IO::Memory.new("122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8".to_slice_from_hexstring)
		MultiHash.decode( io ).should eq( {"sha2-256",32_u64,MultiHash.digest_sha2_256(SAMPLE_TEXT)} )
	end
	it "Decodes sha2-512 hashes" do
		io = IO::Memory.new(("134052eb4dd19f1ec522859e12d89706156570f8fbab1824870bc6f8c7d235eef5f4c"+
                 "2cbbafd365f96fb12b1d98a0334870c2ce90355da25e6a1108a6e17c4aaebb0").to_slice_from_hexstring)
		MultiHash.decode(io).should eq( {"sha2-512",64_u64,MultiHash.digest_sha2_512(SAMPLE_TEXT)} )

	end
  end
  describe "#chech" do
  	it "Verifies sha1 hashes" do
		io = IO::Memory.new("11148a173fd3e32c0fa78b90fe42d305f202244e2739".to_slice_from_hexstring)
		MultiHash.check( io, SAMPLE_TEXT ).should eq(true)

		io.rewind
		MultiHash.check( io, "Some other text" ).should eq(false)
	end
	it "Verifies sha2-256 hashes" do
		io = IO::Memory.new("122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8".to_slice_from_hexstring)
		MultiHash.check( io, SAMPLE_TEXT ).should eq(true)
	
		io.rewind
		MultiHash.check( io, "Some other text" ).should eq(false)
	end
	it "Verifies sha2-512 hashes" do
		io = IO::Memory.new(("134052eb4dd19f1ec522859e12d89706156570f8fbab1824870bc6f8c7d235eef5f4c"+
                 "2cbbafd365f96fb12b1d98a0334870c2ce90355da25e6a1108a6e17c4aaebb0").to_slice_from_hexstring)
		MultiHash.check( io, SAMPLE_TEXT ).should eq(true)

		io.rewind
		MultiHash.check( io, "Some other text" ).should eq(false)
	end
  end

end
