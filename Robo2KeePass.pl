#
# Convert a number of RoboForm html files to a single KeePass XML file
#
# usage: perl Robo2KeePass.pl 
#
# edit this source to set the correct configuration variables (below)
#
# Use roboform to create the html (print-list, save as html - set single column mode) to the base_directory (set $BASE_DIR below)
# e.g.
# i.html (identities)
# p.html (pascards (logins))
# s.html (safenotes)
#
# then run the perl script in this dir to create
# keepass.xml
#
# Finally I suggest using something like axcrypt to securely delete the files containing all your unencrypted passwords.
#
# Version 1.7
#
# $Date$
# $Revision$
# $HeadURL$
#
#
# Changes:
# 2011-01-23 v1.7 Removed reference to unused Data::Dumper package
# 2011-01-23 v1.6 Initial version uploaded to Google Code
#
# Copyright 2011 ianholden.com
# License: BSD License (see end of code)

use strict;
use Encode; # source html is in UTF16 LE (little endian) - need to decode for regex to work

#_________________________________________________
#{ CONFIGURATION:

my $BASE_DIR = "D:/projects/home/roboprint/robo"; # directory to find the roboform source files
my $OUT_FILE = "$BASE_DIR/keepass.xml"; # keepass xml output file

# list the file names (excluding the .html) of the roboform files to process e.g. passwords, identities, safenotes
my @FILE_PREFIXES = ( 
	'i', 
	'p', 
	's',
);

# map each filename to the keepass base group name you would like 
my %BASE_GROUP = ( 
	'i' => 'identities', 
	'p' => 'accounts', 
	's' => 'notes',
); 
my $ROOT_GROUP_NAME='roboform'; # the root group name. this single group will contain the base groups

# define which keepass icon number to use for each base group and the root group
# all subgroups under a basegroup will use the same icon
# the keepassx icon selection dialog shows the icons and their numbers 
my $BASE_GROUP_ICON={
	'default' => 0,
	'roboform' => 29,
	'identities' => 58,
	'accounts' => 1,
	'notes' => 7,
};

# define which keepass icon number to use for each entry within a base group
my $BASE_GROUP_ENTRY_ICON={
	'default' => 0,
	'identities' => 58,
	'accounts' => 0,
	'notes' => 7,
};
#} END OF CONFIGURATION
#_________________________________________________


###########################
use XML::Parser::Expat;

my $INPUT_ENCODING='UTF-16LE'; # Roboform html output files are UTF-16 Little Endian encoded (not UTF-8)

# globals
my $full_group_name='';
my $table_depth=0;
my $caption='';
my $subcaption='';
my $field_name='';
my $field_value='';

my $field_key=''; # use to index current char data being collected into hash $entry_data
my $field_num=0; # fields are captured in their roboform order using this number n as 'name.n' 'value.n' in $entry_data hash
my $entry_data={};

my $get_base_caption=0;
my $base_caption=''; # caption apears in level 1 table for identities - handle like a group

my $group_root = {'name' => $ROOT_GROUP_NAME, 'base_group' => $ROOT_GROUP_NAME, 'entries' => [], 'groups' => {}}; # root of the group structure


my $base_group = '';

if (!open(OUT,">:encoding(UTF-8)", $OUT_FILE)){
	print "ERROR unable to open output file \"$OUT_FILE\" error: \"$!\"\n"; 
}else{

	foreach my $n (@FILE_PREFIXES){
		$base_group = $BASE_GROUP{$n};
		
		my $infile = "$BASE_DIR/$n.html";
		
		print "processing $infile\n";
		
		if (open(IN, "<:encoding($INPUT_ENCODING)", $infile)){
			binmode IN;

			# read the roboform html
			my $filedata = '';
			while(<IN>){
				$filedata .= $_;
			}
			close(IN);
			
			# decode and clean up the html so it is valid xml ready for parsing
			my $data = decode($INPUT_ENCODING,$filedata); # decode the encoded input data for perl regex to work properly on it
			$data =~ s/\x0d\x0a/\n/g; # simplify new lines
			$data =~ s/<WBR>//g; # remove word break tags
			$data =~ s/(\W+\w+=)(\w+)/$1\"$2\"/g; # make attributes (eg. class=caption) quoted so parser thinks it is valid xml
			$data =~ s/&nbsp;/ /g; # &nbsp; to spaces (&nbsp; is not valid in xml)
			$data =~ s/<BR>/\n/ig; # <br> to new line
			
			# parse the xml
			my $parser = new XML::Parser::Expat;
			$parser->setHandlers('Start' => \&sh,
						'End'   => \&eh,
						'Char'  => \&ch);
			$parser->parse($data);
			$parser->finish();
				
		}else{
			print "ERROR unable to open input file \"$infile\" error: \"$!\"\n"; 
		}
	}

	# now all the data is parsed into $group_root  hash we can recursively walk through it and write the KeePass xml
	write_header();
	write_groups($group_root);
	write_footer();
	close(OUT);
	
	print "Finished. KeepPass xml file: '$OUT_FILE' created\n";
	
}
1;

# recursively write out the group hierarchy
sub write_groups{
	my $group=shift;
	my $indent=shift || '';
	
	write_group_start($group->{'name'}, $group->{'base_group'}, $indent);
	
	foreach my $e (@{$group->{'entries'}}){
		write_entry($e, $indent);
	}
	
	foreach my $g (values(%{$group->{'groups'}})){
		write_groups($g, "$indent\t");
	}
	
	write_group_end($indent);
	
}

sub write_header{
	
	print OUT "<!DOCTYPE KEEPASSX_DATABASE>\n<database>\n";
}

sub write_footer{
	print OUT "</database>\n";
}

sub write_entry{
	my $entry = shift; #hash ref
	my $indent=shift || '';
	
	my $user_field = get_best_user_field($entry); 
	my $pw_field = get_best_pw_field($entry);
	
	my $user = "none"; 
	my $pw = '';
	$user = html_safe($entry->{'value.'.$user_field}) if $user_field != 0;
	$pw = html_safe($entry->{'value.'.$pw_field}) if $pw_field != 0;
	
	my $notes = get_notes($entry, $user_field, $pw_field);
	
	print OUT "$indent\t<entry>\n";
	print OUT "$indent\t\t<title>" . html_safe($entry->{'entry_name'}) . "</title>\n";
	my $bg = $entry->{'base_group'};
	my $icon = $BASE_GROUP_ICON->{'default'};
	$icon = $BASE_GROUP_ICON->{$bg} if defined $BASE_GROUP_ICON->{$bg};
	$icon = $BASE_GROUP_ENTRY_ICON->{$bg} if defined $BASE_GROUP_ENTRY_ICON->{$bg};
	print OUT "$indent\t\t<icon>$icon</icon>\n";
	print OUT "$indent\t\t<username>$user</username>\n";
	print OUT "$indent\t\t<password>$pw</password>\n";
	print OUT "$indent\t\t<url>" . html_safe($entry->{'subcaption'}) . "</url>\n";
	print OUT "$indent\t\t<comment>" . html_safe($notes) . "</comment>\n";
	print OUT "$indent\t</entry>\n";
}

sub write_group_start{
	my $name = shift;
	my $bg = shift; # base group
	my $indent=shift || '';

	print OUT "$indent<group>\n";
	print OUT "$indent\t<title>" . html_safe($name) . "</title>\n";
	my $icon = $BASE_GROUP_ICON->{'default'};
	$icon = $BASE_GROUP_ICON->{$bg} if defined $BASE_GROUP_ICON->{$bg};
	print OUT "$indent\t<icon>$icon</icon>\n";
}

sub write_group_end{
	my $indent=shift || '';
	print OUT "$indent</group>\n";
}

# choose the best field to use as the password field and return it's number
sub get_best_pw_field{
	my $entry=shift;

	return get_best_field_matching_regex($entry,'pass|pw|pwd|secur|auth code|authcode'); 
}

# choose the best field to use as the user field and return it's number
sub get_best_user_field{
	my $entry=shift;
	my $pw_field=shift;
	
	return get_best_field_matching_regex($entry,'user|usr|id|login|name', $pw_field); 
}

# find the first field (in roboform order) whose name matches a regex and return it's number or 0 if not found
sub get_best_field_matching_regex{
	my $entry=shift;
	my $regex=shift;
	my $exclude_field=shift||0;
	
	my $best_field=0; # undef
	my $i=1;
	my $got_it=0;
	my $name = $entry->{'name.'.$i};
	while((defined $name) && (!$got_it)){
		if($i != $exclude_field){
			if($name =~ /$regex/i){
				$best_field = $i;
				$got_it=1;
			}
		}
		$i++;
		$name = $entry->{'name.'.$i};
	}
	
	return $best_field;
}


# get the "notes" text (Notes$ in roboform) 
# list all the other fields at the start of this text as there is nowhere else for them in KeePass
# the field names selected as the Username and Password fields are also listed
# if the entry is a "Safenote" we just return the note field
sub get_notes{
	my $entry=shift;
	my $user_field=shift;
	my $pw_field=shift;

	my $i=1;
	my $name = $entry->{'name.'.$i};
	my $other_fields='';
	my $notes='';
	while(defined $name){
		if($i == $pw_field){
			$other_fields .= $name . " : * see Password above\n";
		}
		elsif($i == $user_field){
			$other_fields .= $name . " : * see Username above\n";
		}
		elsif(($i != $pw_field) && ($i != $user_field)){
			my $value = $entry->{'value.' . $i};
			if($name eq 'Note$'){
				$notes = $value;
			}else{
				$other_fields .= $name . " : " . $value . "\n"; 
			}
		}	
		$i++;
		$name = $entry->{'name.'.$i};
	}

	# check for safenotes style entries
	if (($user_field == 0) && ($pw_field == 0) && ($i <= 1)){
		return $entry->{'value.0'}; # just return the contents of the single note field that will be in value.0
	}

	return "Fields:\n$other_fields\n\nNotes:\n$notes";

}

# make string safe for insertion between html tags and preserve new lines in the same way KeePass does
sub html_safe{
	my $data = shift;
	$data =~ s/&/&amp;/g;
	$data =~ s/</&gt;/g;
	$data =~ s/[\r\n]+/<br\/>/g;
	return $data;
}


# add a completed entry to the group structure
sub process_field{
	# $entry_data has all the values
	
	my $entry_name =  $entry_data->{'caption'};
	if (!defined $entry_name){
		$entry_name = $base_caption . "\\" . $entry_data->{'subcaption'};
		$entry_data->{'subcaption'}='';
	}
		
	my $group = find_or_create_group($group_root, $entry_name);
	
	if ($entry_name =~ /^(.*)\\+(.*?)$/ ){
		$entry_name = $2;
	}
	
	# add this entry data
	$entry_data->{'entry_name'} = $entry_name;
	my %entry = %$entry_data; # copy it
	push(@{$group->{'entries'}},\%entry); 
	
}

# return the lowest level group that this "caption" belongs to
# build the group structure as we go if necessary
sub find_or_create_group{
	my $group = shift;
	my $caption = shift;

	# the group hierarchy is at the start fo the caption separated by backslash \
	# strip off one group level at a time and recursively search the hierarchy for the lowest level group
	# creating groups as we go if they don't already exist
	if($caption =~ /^(.*?)\\+(.*)$/ ){
		my $group_name = $1;
		$caption = $2;
		
		my $groups = $group->{'groups'};
		if (!defined $groups->{$group_name}){
			my $new_group = {};
			$new_group->{'name'} = $group_name;
			$new_group->{'base_group'} = $base_group; # set from current global value
			$new_group->{'entries'} = [];
			$new_group->{'groups'} = {};
			$groups->{$group_name}=$new_group; # create it
			
		}
		return find_or_create_group($groups->{$group_name}, $caption);
	}
	return $group;
}



# xml parse functions

sub sh # start tag
{
	my ($p, $el, %atts) = @_;

	if ($el eq 'TABLE'){
		$table_depth++;
		if($table_depth==2){
			$entry_data={}; # start a new clean entry
			$entry_data->{'base_group'} = $base_group;
			$field_num=0;
		}
	}
	
	if ($el eq 'TD'){
		if($table_depth == 1){
			# identities have the "caption" in the level 1 table
			if ($atts{'class'} eq 'caption'){
				$get_base_caption=1;
				$base_caption=$base_group . "\\";
			}
		}
		if($table_depth == 2){
			if ($atts{'class'} eq 'caption'){
				$field_key = 'caption';
				$entry_data->{'caption'} = $base_group."\\";
			}
			elsif ($atts{'class'} eq 'subcaption'){
				$field_key = 'subcaption';
			}
			elsif ($atts{'class'} eq 'field'){
				$field_num++;
				$field_key = 'name.'.$field_num;
			}
			elsif ($atts{'class'} eq 'wordbreakfield'){
				$field_key = 'value.'.$field_num;
			}
			else{
				$field_key='';
			}
		}
	}
}

sub eh # end tag
{
	my ($p, $el) = @_;

	if ($el eq 'TABLE'){
		if($table_depth == 2){
			#print "Data complete:\n" . Dumper($entry_data);
			process_field();
		}
		$table_depth--;
	}
	if ($el eq 'TD'){
		$field_key='';
	}
	if (($el eq 'TD') && ($table_depth == 1)){
		$get_base_caption=0;
	}

}

sub ch # character data between tags
{
	my ($p, $el) = @_;
	if($field_key ne ''){
		$entry_data->{$field_key}='' if !defined $entry_data->{$field_key};
		$entry_data->{$field_key} .= $el;
	}
	if($get_base_caption){
		$base_caption .= $el;
	}   	
}

#--------------------------------------------------------------------------------
# BSD License:
#
# Copyright (c) 2011, ianholden.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this 
# list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this 
# list of conditions and the following disclaimer in the documentation and/or 
# other materials provided with the distribution.
#
# Neither the name of ianholden.com nor the names of its contributors may be used 
# to endorse or promote products derived from this software without specific prior 
# written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR 
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#--------------------------------------------------------------------------------
1;