require 'win32ole'

word=WIN32OLE.new('Word.Application')
word.visible=true
path=File.dirname(File.expand_path(__FILE__))
fso=WIN32OLE.new("Scripting.FileSystemObject")
path=fso.getabsolutepathname "foo.doc"
word.documents.open File.join(path)
word.dialogs.each {|d| p d.GetTypeInfo}


