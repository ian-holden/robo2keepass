# Convert Roboform to KeePassX #

This perl script will convert the RoboForm password manager Passcards, Identities and Safenotes to a KeePassX XML file that may be imported into KeePassX or KeePass v2.

## Features ##

  * Converts any number of Roboform Passcards, Identities and Safenotes to a single KeePassX XML file for importing.
  * The Roboform group (folder) structure is maintained
  * Automatic selection of best user and password fields
  * Any extra fields are placed into the top of the KeePass Comment field
  * You can configure which icons to use for each of the main groups and their entries.

## How to use ##

First you need to **export your passcards/identities/safenotes** to a HTML file.

To do this, open RoboForm's Passcard/Identity/Safenote Editor (e.g. 'Edit Passcards' in the Windows start menu)
and in the editor's main menu go 'Passcard' -> 'Print List'.

In the dialog that opens, select **"Columns: 1"**, Tick **"Full URL"** and click the **'Save'** button. Choose a location and file name, and click 'Save'.

Create an html file for all the RoboForm data you want to import. This might be i.html, s.html and p.html for identities, safenotes and passcards respectively.

Now using a text editor (e.g. notepad) edit the Robo2KeePass.pl file and change the configuration values to match your files.

In a command window, CD to the directory containing Robo2KeePass.pl and run it like this:

```
perl Robo2KeePass.pl
```

The xml file produced may now be imported into KeePassX or KeePass v2

### Use with KeePassX ###
File > Import from... > KeePassX XML

### Use with KeePass v2 ###
File > Import... > KeePassX xml file (under Password Managers)

_Use with KeePass v1 is not supported._


**You need Perl.** Most Linux systems will have this. Windows users can easily install ActivePerl community Edition from http://www.activestate.com/activeperl/downloads
As you are using Roboform, you are a Windows user, so I recommend running the script on windows after installing Active Perl if you need to as this should work without needing any special tweaking.

---
## Further info that may help if you can't get the script to run ##

The script uses two modules: Encode and XML::Parser::Expat
These modules will probably be already installed. If not, Perl will complain about them being missing when you run the script.
To install the modules, either use the Perl Package Manager (ppm), or CPAN e.g.

In a command window:
```
ppm install Encode
ppm install XML-Parser
```

or (as root, or using sudo e.g. sudo perl -MCPAN -e shell)
```
perl -MCPAN -e shell
cpan> o conf prerequisites_policy follow
cpan> install Encode
cpan> install XML::Parser
cpan> q
```

It's possible you may also need to install libxml-parser-perl on linux e.g. sudo apt-get install libxml-parser-perl.