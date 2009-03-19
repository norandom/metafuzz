require 'socket'

#Establish a 'connection' over raw IP. The OS will provide the
#IP header.
#
#Parameters: dest_host (string), ip_proto (0-255 or Socket constant)
module CONN_RAWIP

    #These methods will override the stubs present in the Connector
    #class, and implement the protocol specific functionality for 
    #these generic functions.
    #
    #Arguments required to set up the connection are stored in the
    #Connector instance variable @module_args.
    #
    #Errors should be handled at the Module level (ie here), since Connector
    #just assumes everything is going to plan.

    #Set up a new socket.
    def establish_connection
        @dest, @proto = @module_args
        unless @proto.is_a? Fixnum and (0..255) === @proto
            raise ArgumentError, "RAWIP: establish: protocol must be 0-255"
        end
        begin
            @addr=Socket.pack_sockaddr_in(1024, @dest)
        rescue
            raise ArgumentError, "RAWIP: establish: bad destination (#{@dest})"
        end
        begin
            BasicSocket.do_not_reverse_lookup=true
            @rsock=Socket.open(Socket::PF_INET, Socket::SOCK_RAW, @proto)
            @ssock=Socket.open(Socket::PF_INET, Socket::SOCK_RAW, @proto)
            # Let the OS build the IP header. No IP_HDRINCL on Windows?
            @ssock.setsockopt(Socket::SOL_IP, Socket::IP_HDRINCL, false) if Socket::Constants.constants.include? "IP_HDRINCL"
            @connected=true
        rescue Errno::EPERM
            raise ArgumentError, "RAWIP: establish: need root access for raw sockets!"
        rescue
            destroy_connection
            raise RuntimeError, "RAWIP: establish: couldn't establish socket. (#{$!})"
        end
    end

    #Blocking read from the socket.
    def blocking_read
        raise RuntimeError, "RAWIP: blocking_read: Not connected!" unless connected?
        begin
            loop do
                data, sender = @rsock.recvfrom(8192)
                port, host = Socket.unpack_sockaddr_in(sender)
                #Assume a 20 byte IP header (yuck!)
                return data[20..-1] if host == @dest # only queue packets from our peer
            end
        rescue
            destroy_connection
            raise RuntimeError, "RAWIP: blocking_read: Couldn't read from socket! (#{$!})"
        end
    end

    #Blocking write to the socket.
    def blocking_write( data )
        raise RuntimeError, "RAWIP: blocking_write: Not connected!" unless connected?
        begin
            @ssock.send(data, 0, @addr)
        rescue
            destroy_connection
            raise RuntimeError, "RAWIP: blocking_write: Couldn't write to socket! (#{$!})"
        end
    end

    #Return a boolen.
    def is_connected?
        @connected
    end

    #Cleanly destroy the socket. 
    def destroy_connection
        begin
            @ssock.close if @ssock
            @rsock.close if @rsock
        ensure
            @connected=false
        end
    end

end
