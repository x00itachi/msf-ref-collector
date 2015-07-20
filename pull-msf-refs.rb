	<ruby>

	refsfile = File.open("msfrefs.csv", "w")

	reftypes = {
		'cve' => [/\/cve\/\d+-\d+/i, /\/cve\/(\d+-\d+)/i],
		'osvdb' => [/\.osvdb\.\w+\/\d+/i, /osvdb\.\w+\/(\d+)/i],
		'bid' => [/\/bid\/\d+/i, /\/bid\/(\d+)/i],
		'edb' => [/\.exploit-db\.\w+\/exploits\/\d+/i, /\.exploit-db.\w+\/exploits\/(\d+)/i],
		'msb' => [/\.microsoft\.\w+\/[\w-]+\/security\/bulletin\//i, /\/bulletin\/(MS\d+-\d+)/i],
		'zdi' => [/\.zerodayinitiative\.\w+\/advisories\/ZDI/i, /\/advisories\/ZDI-(\d+-\d+)/i],
		'uscert' => [/\.kb\.cert\.\w+\/vuls\/id\/\d+/i, /\/vuls\/id\/(\d+)/i],
	}

	framework.exploits.keys.sort.map do |exp|
		exploit = framework.exploits.create(exp)
		refsline = ""

		if !exploit.nil? and exploit.references.any?
			exploit.references.each do |ref|
				ref = ref.to_s

				if ref =~ reftypes['cve'][0]
					cve = ref.match(reftypes['cve'][1])[1]
					refsline = refsline + "CVE-#{cve};" 

				elsif ref =~ reftypes['osvdb'][0]
					osvdb = ref.match(reftypes['osvdb'][1])[1]
					refsline = refsline + "OSVDB-#{osvdb};"

				elsif ref =~ reftypes['bid'][0]
					bid = ref.match(reftypes['bid'][1])[1]
					refsline = refsline + "BID-#{bid};"

				elsif ref =~ reftypes['edb'][0]
					edb = ref.match(reftypes['edb'][1])[1]
					refsline = refsline + "EDB-#{edb};"

				elsif ref =~ reftypes['msb'][0]
					msb = ref.match(reftypes['msb'][1])[1]
					refsline = refsline + "MSB-#{msb};"

				elsif ref =~ reftypes['zdi'][0]
					zdi = ref.match(reftypes['zdi'][1])[1]
					refsline = refsline + "ZDI-#{zdi};"

				elsif ref =~ reftypes['uscert'][0]
					uscert = ref.match(reftypes['uscert'][1])[1]
					refsline = refsline + "US-CERT-VU-#{uscert};"

				else
					refsline = refsline + "URL-#{ref};"
				end

			end
			refsline.gsub!(/;$/, '')
			puts "#{exp},#{refsline}"
			refsfile.puts "#{exp},#{refsline}"

		else
			puts "#{exp},No-references"
			refsfile.puts "#{exp},No-references"

		end
	end

	refsfile.close

	</ruby>