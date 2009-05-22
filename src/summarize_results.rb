path=ARGV[0]

# get all detail files in the path
pattern=File.join(path, "detail*.txt")
results=Hash.new {|hsh, k| hsh[k]=[0,""]}
Dir.glob(pattern, File::FNM_DOTMATCH).each {|fn|
    contents=File.open(fn, "rb") {|ios| ios.read}
    if match=contents.match(/Hash=(.*)\)/)
        bucket=match[1]
        results[bucket][0]+=1
        next if results[bucket][0] > 1
        title=contents.scan(/^DESCRIPTION.*$/).join
        classification=contents.scan(/^CLASSIFICATION.*$/).join
        instructions=contents.scan(/^BASIC_BLOCK_INSTRUCTION:.*$/).join("\n")
        results[bucket][1]=[title, instructions, classification].join("\n")
    end
}

results.sort.each {|k,v|
    puts "--- #{k} (count: #{v[0]}) ---"
    puts v[1]
}


