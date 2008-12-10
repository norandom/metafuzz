require 'windows_manipulation'
require 'Win32API'

BMCLICK=0x00F5
WM_DESTROY=0x0010


def kill_dialog_boxes
    #closeHandle = Win32API.new("kernel32", "CloseHandle", ['L'],'I')
    wm=WindowOperations.new
    my_result=wm.do_enum_windows {|k,v| v[:classname] =~ /OpusApp/ }
    wm.close
    wm=nil
=begin
    my_result.each {|word_hwnd,child|
        children=Wm.do_enum_windows {|k,v| v[:parent_window]==word_hwnd}
        child[:children]=children
        close_handle.call word_hwnd
    }
    # my_result is now Word windows with their toplevel children
    my_result.each {|k,v|
        if v[:children]
            v[:children].each {|k,v|
                if v[:classname]=~/bosa_sdm/
                    Wm.send_window_message(k, WM_DESTROY)
                end
                if v[:classname]=~/32770/
                    Wm.switch_to_window(k)
                    Wm.do_child_windows(k) {|k,v| v[:classname]=="Button" and (v[:caption]=="OK" or v[:caption]=="&No")}.each {|k,v|
                        Wm.send_window_message(k, BMCLICK)
                    }
                end
                close_handle.call k
            }
        end
    }
    my_result=nil
=end
end
class Object
  def memory_profile_size_of_object(seen={})
    return 0 if seen.has_key? object_id
    seen[object_id] = true
    count = 1
    if kind_of? Hash
      each_pair do |key,value|
        count += key.memory_profile_size_of_object(seen)
        count += value.memory_profile_size_of_object(seen)
      end
    elsif kind_of? Array
      count += size
      each do |element|
        count += element.memory_profile_size_of_object(seen)
      end
    end

    count += instance_variables.size
    instance_variables.each do |var|
      count += instance_variable_get(var.to_sym).memory_profile_size_of_object(seen)
    end

    count
  end

  def memory_profile_inspect(seen={},level=0)
    return object_id.to_s if seen.has_key? object_id
    seen[object_id] = true
    result = ' '*level
    if kind_of? Hash
      result += "{\n" + ' '*level
      each_pair do |key,value|
        result += key.memory_profile_inspect(seen,level+1) + "=>\n"
        result += value.memory_profile_inspect(seen,level+2) + ",\n" + ' '*level
      end
      result += "}\n" + ' '*level
    elsif kind_of? Array
      result += "[\n" + ' '*level
      each do |element|
        result += element.memory_profile_inspect(seen,level+1) + ",\n" + ' '*level
      end
      result += "]\n" + ' '*level
    elsif kind_of? String
      result += self
    elsif kind_of? Numeric
      result += self.to_s
    elsif kind_of? Class
      result += to_s
    else
      result += "---"+self.class.to_s + "---\n" + ' '*level
    end


    instance_variables.each do |var|
      result += var + "=" + instance_variable_get(var.to_sym).memory_profile_inspect(seen,level+1) + "\n" + ' '*level
    end

    result
  end

end


1000.times do |i|
    begin
        kill_dialog_boxes
        objects = Hash.new(0)
        print "#{ObjectSpace.each_object(Hash){}}"
        print "\r"
    rescue 
        puts "Wordslayer: DK: #{$!}"
    end
    sleep(0.1)
  end
  
   ObjectSpace::garbage_collect
    sleep 10 # Give the GC thread a chance
    all = []
    ObjectSpace.each_object do |obj|
      next if obj.object_id == all.object_id 
      all << obj
    end
    
    tally = Hash.new(0)
    max_obj = nil
    max_count = 0
    all.each do |obj|
      count = obj.memory_profile_size_of_object
      if max_count < count
        max_obj = obj
        max_count = count
      end
      
      tally[obj.class]+=count
    end
    

      puts '+'*70
      tally.keys.sort{|a,b| 
        if tally[a] == tally[b]
          a.to_s <=> b.to_s
        else
          -1*(tally[a]<=>tally[b])
        end
      }.each do |klass|
        puts "#{klass}\t#{tally[klass]}"
      end
      
    puts '-'*70
      puts "Max obj was #{max_obj.class} at #{max_count}"

