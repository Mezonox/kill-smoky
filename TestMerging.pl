#!/usr/bin/perl

use strict;
use Getopt::Long;

my $alteron = 0;

my $BaseFile = "fork.c";


&ParseArgs();

#If $alteron true then ChangeFiles, otherwise GenerateFiles
if($alteron){
	&ChangeFiles();
}
else{
	&GenerateFiles();
}


sub ParseArgs{
	GetOptions(
	"a" => \$alteron
	)
	or die "Error in command line args!\n";

}

sub ChangeFiles{
	print "Changing files here...\n";
}

sub GenerateFiles{
	print "Generate files here...\n";
	
	open(my $baseHandle, "<", $BaseFile) or die "Can't open $BaseFile for input $!";
	
	my @FileContents = <$baseHandle>;
	
	#1000 files to create
	my $fileCount = 1000;
	my $counter = 0;
	my $baseName = "ForkingMess";
	
	for($counter = 0;$counter < 1000; $counter++){
		if($counter < 300){
			my $filename = $baseName."$counter".".txt"; 
			open(my $countHandle, ">", $filename) or die "Can't open $filename for output $!";
			print $countHandle @FileContents;
			close($countHandle);
		}
	}
	
	#print @FileContents;
	
	close($baseHandle);
}