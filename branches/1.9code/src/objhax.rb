#A collection of useful code bits that have been pilfered from various sources on the Interweb.
=begin
if (require 'inline' rescue false)
class Class
    inline do |builder|

        builder.c %{
VALUE get_attached() {
            if(FL_TEST(self, FL_SINGLETON))
                return rb_iv_get(self, "__attached__");
            else
                return Qnil;
        }
}

        builder.c %{
VALUE set_attached(VALUE obj) {
            if(FL_TEST(self, FL_SINGLETON)) {
            rb_iv_set(self, "__attached__", obj);
            return self;
        }
            else
                return Qnil;
        }
}

    end
end
end
=end
        class Object
            #Return the metaclass of an object.
            def metaclass; class << self; self; end; end

        #Run a  block in the context of the metaclass.
        def meta_eval &blk; metaclass.instance_eval &blk; end

        # Adds methods to a metaclass
        def meta_def name, &blk
            meta_eval { define_method name, &blk }
        end

        # Defines an instance method within a class
        def class_def name, &blk
            class_eval { define_method name, &blk }
        end

        # Deep copy of objects that can be handled with Marshal
        def deep_copy
            Marshal.load(Marshal.dump(self))
        end

        #Define, run and then undefine a method to fake instance_eval with arguments
        def instance_exec(*args, &block)
            mname = "__instance_exec_#{Thread.current.object_id.abs}"
            class << self; self end.class_eval{ define_method(mname, &block) }
            begin
                ret = send(mname, *args)
            ensure
                class << self; self end.class_eval{ undef_method(mname) } rescue nil
            end
            ret
        end
    end
