#!/usr/bin/perl

use strict;
use Getopt::Long;

my $alteron = 0;

my $BaseFile = "fork.c";
my $alterFile = "Messiness.c";

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
	my $filehandle;
	my @listOfFiles = `find . -name \\*.c`;
	print "starting a count\n";
	
	my $counter = 0;
	
	open($filehandle, "<", $alterFile) or die "Can't open $alterFile for input $!";
	my @alterContents = <$filehandle>;
	close($filehandle);
	
	foreach my $file (@listOfFiles){
		chomp $file;
		open($filehandle, "<", $file) or die "Can't open $file for input $!";
		my @origFileContents = <$filehandle>;
		close($filehandle);
		
		open($filehandle, ">", $file) or die "Can't open $file for output $!";
		foreach my $line(@origFileContents){
			chomp $line;
			#every 20 slocs
			if($counter % 20 == 0){
				print $filehandle $alterContents[$counter];
			}
			print $filehandle $line;
		}
		close($filehandle);
		$counter++;
	}
	
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
			my $filename = $baseName."$counter".".c"; 
			open(my $countHandle, ">", $filename) or die "Can't open $filename for output $!";
			print $countHandle @FileContents;
			close($countHandle);
		}
		elsif($counter < 600){
			my $dir = "directory_".$counter;
			`mkdir $dir`;
			
			my $filename = $dir."/".$baseName."$counter".".c";
			open(my $countHandle, ">", $filename) or die "Can't open $filename for output $!";
			print $countHandle @FileContents;
			close($countHandle);
		}
		else{
			my $dir = "directory_".$counter;
			`mkdir -p Level2/$dir`;
			if(-d "Level2"){
			my $filename = "Level2/".$dir."/".$baseName."$counter".".c";
			open(my $countHandle, ">", $filename) or die "Can't open $filename for output $!";
			print $countHandle @FileContents;
			close($countHandle);
			}
			else{
				print "Level2 doesn't exist!\n";
			}
			
		}
	}
	
	#print @FileContents;
	
	close($baseHandle);
}
