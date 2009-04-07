#:main:intro.rb
#
#==Metafuzz 0.3
#=A framework for building fuzzers that use metadata
#
#There are four main components. Follow the links for more information.
#
#* Binstruct - A class that can be used to define protocol elements, like headers and packets
#* FSA - A class that can be used to build simple finite state automata to describe and automate protocols
#* Generators - A bunch of new Generator classes that can be combined to create all sorts of output
#* Fuzzer - An example fuzzer that uses Binstruct metadata to decide what output to create.
#
#What's not included
#
#* Delivery - How you get your output to your target is up to you (network, file, RPC, memory injection etc)
#* Instrumentation - Working out if the target crashed, or what output made it crash, is also up to you
#
#To create a basic fuzzer for a new network based protocol you would do the following
#1. Create Binstruct classes for the protocol headers (PPTP definitions are in the examples directory)
#2. Optional: Create an FSA object to help keep track of stateful elements like cookies, nonces, transaction ids etc
#3. Create a Fuzzer for each basic protocol element (like a packet type)
#4. Send the output. This can be done quickly with an FSA object, allowing all sendable packets to be fuzzed by recursing over the FSA graph.
#
#
#Author:: Ben Nagy
#Copyright:: Copyright (c) Ben Nagy, 2006.
#License:: All components of this framework are licensed under the Common Public License 1.0. Please read LICENSE.TXT or see the RDoc for license.rb for details.