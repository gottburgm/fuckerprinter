#!/usr/bin/perl

use 5.10.0;

use strict;
use warnings;

no warnings 'experimental';

use Term::ANSIColor qw(colored color);
use Scalar::Util qw(reftype);
use JSON;
use JSON::Parse qw(json_file_to_perl);
use Digest::MD5 qw(md5_hex);
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Cookies;
use HTTP::Response;
use Getopt::Long;

=pod

=head1 0

=head2 Date
<DATE>

=head2 Reporter(s)
<AUTHOR>

=head2 Description 
<DESCRIPTION>

=cut

# Global Variables
my $verbose = 0;           # Command Argument : verbose
my $debug = 0;             # Command Argument : debug

# Display The Header
header();

# Run The MOFO Fingerprinter
fingerprint();


sub header {
    print "\n\n";
    my $title = "=================================[ Multiple Webapps Fingerprinter ]=================================";
    
    print qq{
$title
 ____                  __                                                __                   
/\\  _`\\               /\\ \\                                    __        /\\ \\__                
\\ \\ \\L\\_\\__  __    ___\\ \\ \\/'\\      __   _ __   _____   _ __ /\\_\\    ___\\ \\ ,_\\    __   _ __  
 \\ \\  _\\/\\ \\/\\ \\  /'___\\ \\ , <    /'__`\\/\\`'__\\/\\ '__`\\/\\`'__\\/\\ \\ /' _ `\\ \\ \\/  /'__`\\/\\`'__\\
  \\ \\ \\/\\ \\ \\_\\ \\/\\ \\__/\\ \\ \\\\`\\ /\\  __/\\ \\ \\/ \\ \\ \\L\\ \\ \\ \\/ \\ \\ \\/\\ \\/\\ \\ \\ \\_/\\  __/\\ \\ \\/ 
   \\ \\_\\ \\ \\____/\\ \\____\\\\ \\_\\ \\_\\ \\____\\\\ \\_\\  \\ \\ ,__/\\ \\_\\  \\ \\_\\ \\_\\ \\_\\ \\__\\ \\____\\\\ \\_\\ 
    \\/_/  \\/___/  \\/____/ \\/_/\\/_/\\/____/ \\/_/   \\ \\ \\/  \\/_/   \\/_/\\/_/\\/_/\\/__/\\/____/ \\/_/ 
                                                  \\ \\_\\                                       
                                                   \\/_/                                       

    By gottburgm (https://github.com/gottburgm/)
    Deutschland Über Alles !
};
    print "="x(length($title)) . "\n\n";
}

sub exploit_header {
    system("clear");
    print color("red");

    
    print color("green");
    print "\nGithub : https://github.com/gottburgm/\n";
    print "\n\n";
}

sub showList {
    my @services_names = ();
    
    print "\n";
    print qq{
        
        # Currently Supported Services
        
};

    opendir(DIRECTORY, "./data/") or die error("couldn't open directory: ./data (" . $! . ")");
    while(my $service_directory = readdir(DIRECTORY)) {
        next if($service_directory eq '.' || $service_directory eq '..');
        push(@services_names, uc($service_directory));
    }
    close DIRECTORY;
    
    foreach my $service_name (@services_names) {
        print color("white") . "\t- " . color("green") . $service_name . "\n"; 
    }
    print "\n\n";
}

sub showHelp {
    print "\n";
    print qq{  

        # Usage
        
            perl $0  --url URL [OPTIONS] --service NAME1,NAME2,...
            perl $0  --urls-file FILE [OPTIONS] --service NAME1,NAME2,...
        
        
        # Arguments
        
            --url [VALUE]        : The target URL [Format: scheme://host]
            --urls-file [FILE]   : The path to the list of urls to test
            --hash-check         : Try to get version(s) by requesting default files and comparing their checksum
            
            --user-agent [VALUE] : User-Agent to send to the server
            --cookie [VALUE]     : Cookie string to use
            --proxy [VALUE]      : Proxy server to use [Format: scheme://host:port]
            --timeout [VALUE]    : Max timeout for The HTTP requests
            --auth [VALUE]       : Credentials to use for HTTP login [Format: username:password]
            --help               : Display this help menu
            --verbose            : Be more verbose
            --debug              : Debug mode, display each requests
    };
    print "\n\n";
    exit;
}

sub buildRequester {
    my ($timeout, $useragent, $cookie_string, $proxy ) = @_;
    $cookie_string = 0 if(!defined($cookie_string));
    $proxy = 0 if(!defined($proxy));
    my $browser = 0;
    my $cookie_jar = 0;
    
    $cookie_jar = HTTP::Cookies->new(
        file     => "/tmp/cookies.lwp",
        autosave => 1,
    );
    
    $browser = LWP::UserAgent->new();
    $browser->protocols_allowed( [qw( http https ftp )] );
    $browser->requests_redirectable(['GET', 'PUT', 'DELETE', 'POST', 'HEAD', 'OPTIONS']);
    $browser->cookie_jar( $cookie_jar);
    
    ### Custom Options
    $browser->timeout($timeout);
    $browser->agent($useragent);
    $browser->default_header('Cookie' => $cookie_string) if($cookie_string);
    
    if($proxy) {
        if($proxy =~ /([a-z])+:\/\/.*:([0-9])+/i) {
            $browser->proxy( [qw( http https ftp ftps )] => $proxy);
        } else {
            error("Wrong proxy string given, please only use the following format : scheme://host:port");
        }
    }
    
    return $browser;
}

sub buildRequest {
    my ( $url, $method, $payload, $content_type) = @_;
    $content_type = 'application/x-www-form-urlencoded' if(!defined($content_type) || !$content_type);
    $payload = '' if(!defined($payload) || !$payload);
    $method = uc($method);
    my $request = 0;
    
    if($method eq "GET") {
        if($payload) {
            $payload = '?' . $payload;
            $request = new HTTP::Request $method, $url . $payload;
        } else {
            $request = new HTTP::Request $method, $url
        }
    } else {
        $request = new HTTP::Request $method, $url;
        $request->content($payload) if($payload);
        $request->content_type($content_type);
    }
    $request->header(Accept => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
        
    return $request;
}

sub fingerprint {
    my $browser = 0;
    my $identifications_file = 'data/identifications.json';
    
    my $services_inline = 0; # Command Argument : service
    my $proxy = 0;           # Command Argument : proxy
    my $timeout = 30;        # Command Argument : timeout
    my $single_url = 0;      # Command Argument : url
    my $urls_file = 0;       # Command Argument : urls-file
    my $hash_check = 0;      # Command Argument : hash-check
    my $cookie_string = 0;   # Command Argument : cookie
    my $useragent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:54.0) Gecko/20100101 Firefox/54.0";   # Command Argument : user-agent
    my $auth = 0;            # Command Argument : auth
    my $content_type = 0;    # 
    my $payload = 0;         # If we need to support POST/PUT/.. requests
    
    my @services = ();
    my @urls = ();
    
    my $identifications_data = {};
    my $results_data = {};
    
    GetOptions(
        "service=s"     => \$services_inline,
    	"proxy=s"		=> \$proxy,
    	"debug!"		=> \$debug,
    	"verbose!"		=> \$verbose,
    	"timeout=i"		=> \$timeout,
    	"url=s"		    => \$single_url,
    	"urls-file=s"   => \$urls_file,
    	"hash-check!"   => \$hash_check,
    	"cookie=s"		=> \$cookie_string,
    	"help!"		    => \&showHelp,
    	"list!"		    => \&showList,
    	"user-agent=s"	=> \$useragent,
    ) or error("Bad Value(s) Provided In Command Line Arguments");

    ### Required Arguments
    die error("Required argument(s) missing .") if(!$services_inline || (!$single_url && !$urls_file));    
    exploit_header();
    
    @services = split(',', $services_inline);
    
    if($single_url) {
        push(@urls, $single_url);
    } elsif($urls_file) {
        push(@urls, read_file($urls_file, 1));
    }
    
    if(-f $identifications_file) {
        $identifications_data = json_file_to_perl($identifications_file);
    } else {
        die error("Missing identifications file: $identifications_file");
    }
    
    URLS: foreach my $url (@urls) {
        $url .= '/' if(substr($url, -1) ne '/');

        foreach my $service_name (@services) {
            my $service_directory = "data/" . lc($service_name);

            if(-d $service_directory) {
                info("Testing for web service: " . color("cyan") . uc($service_name) . " on: " . color("cyan") . $url);
                
                ### Setting Up The Requester
                $browser = buildRequester($timeout, $useragent, $cookie_string, $proxy);
    
                ### Files & variables
                my $install_paths_list = "$service_directory/lists/install_paths.txt";
                my $default_files_list = "$service_directory/lists/default_files.txt";
                my $hash_files_requests_file = "$service_directory/requests/hash_files_fingerprint.json";
                my $regexes_file = "$service_directory/regexes.json";
                
                my @installation_paths = ();
                my @default_files_paths = ();
                
                ### Data
                my $default_files_requests_data = {};
                my $hash_files_requests_data = {};
                my $regexes_data = {};
                
                if(-f $install_paths_list) {
                    push(@installation_paths, read_file($install_paths_list, 1));
                } else {
                    die error("Couldn't open installation paths list file: $install_paths_list");
                }
                
                if(-f $default_files_list) {
                    push(@default_files_paths, read_file($default_files_list, 1));
                    
                    foreach my $default_file_path (@default_files_paths) {
                        $default_files_requests_data->{$default_file_path}->{TEXT} = 'Requesting ' . uc($service_name) . ' Default File: ' . $default_file_path;
                        $default_files_requests_data->{$default_file_path}->{METHOD} = 'GET';
                        $default_files_requests_data->{$default_file_path}->{PATH} = $default_file_path;
                    }
                } else {
                    die error("Couldn't open default files list file: $default_files_list");
                }
                
                if(-f $regexes_file) {
                    $regexes_data = json_file_to_perl($regexes_file);
                } else {
                    die error("Couldn't open JSON regexes file: $regexes_file");
                }
    
                if($hash_check) {
                    if(-f $hash_files_requests_file) {
                        $hash_files_requests_data = json_file_to_perl($hash_files_requests_file);
                    } else {
                        die error("Couldn't open JSON requests file: $hash_files_requests_file");
                    }
                }
                
                ### Identifications from index response
                $results_data->{$url} = services_identifications($browser, $identifications_data, $url);
                
                ### Default files fingerprint
                $results_data->{$url}->{lc($service_name)} = default_files_fingerprint($browser, $default_files_requests_data, $regexes_data, $url);
                
                ### Hash files fingerprint
                if(!$results_data->{$url}->{lc($service_name)}->{versions} && $hash_check) {
                    $results_data->{$url}->{lc($service_name)}->{versions} = hash_files_fingerprint($browser, $hash_files_requests_data, $url);
                }
                
                if($results_data->{$url}->{lc($service_name)}->{versions}) {
                    my $versions = $results_data->{$url}->{lc($service_name)}->{versions};
                    result(color("yellow") . "\t[" . color("red") . uc($service_name) . color("yellow") . ']' . color("blue") . " version(s) " . color("yellow") . '[' . color("red") . $versions . color("yellow") . ']' . color("blue") . " found for: " . color("cyan") . $url);
                    
                    foreach my $data_type (sort keys %{ $results_data->{$url}->{lc($service_name)} }) {
                        next if($data_type eq "versions" || !(0+@{ $results_data->{$url}->{lc($service_name)}->{$data_type} }));
                        result(ucfirst($data_type . " found :"));
                        
                        foreach my $data_item (@{ $results_data->{$url}->{lc($service_name)}->{$data_type} }) {
                            print color("white") . "\t - " . color("green") . $data_item . "\n";
                        }
                        print "\n\n";
                    }
                } else {
                    warning("Any " . lc($service_name) . " version(s) found for: $url");
                }
            } else {
                die error("An unknown or non-implemented service has been provided: $service_name");
            }
        }
    }
}

sub services_identifications {
    my ( $browser, $identifications_data, $url ) = @_;
    
    info("Sending a GET request on: " . color("cyan") . $url . " to run identifications tests on the response ...");
    my $request = buildRequest($url, 'GET');
    my $response = $browser->request($request);
    displayResponse($response) if($debug);
    
    my $results = {};
    
    foreach my $service_name (sort keys %{ $identifications_data }) {
        foreach my $detection_type (sort keys %{ $identifications_data->{$service_name} }) {
            if($detection_type =~ /^MATCHES$/i) {
                foreach my $match_string (@{ $identifications_data->{$service_name}->{$detection_type} }) {
                    push(@{ $results->{$service_name}->{matches}->{$response->request->uri} }, $match_string) if($response->content =~ /$match_string/i || $response->decoded_content =~ /$match_string/i);
                }
            } elsif($detection_type =~ /^HEADERS?/i) {
                foreach my $header_name (keys %{ $identifications_data->{$service_name}->{$detection_type}->{HEADERS} }) {
                    if($response->header($header_name)) {
                        my @header_values = ();
                        push(@header_values, $response->header($header_name));
                        
                        foreach my $header_value (@header_values) {
                            foreach my $match_string (@{ $identifications_data->{$service_name}->{$detection_type}->{HEADERS}->{$header_name} }) {
                                push(@{ $results->{$service_name}->{matches}->{$response->request->uri}->{headers}->{"$header_name:$header_value"} }, $match_string) if($header_value =~ /$match_string/i);
                            }
                        }
                    }
                }
            }
        }
    }

    return $results;
}

sub default_files_fingerprint {
    my ( $browser, $requests_data, $regexes_data, $url) = @_;
    
    my $results = {};
    
    ### Build/send the requests
    foreach my $file (sort keys %{ $requests_data }) {
        last if($results->{versions});
        my $method = $requests_data->{$file}->{METHOD};
        my $request_url = $url . $requests_data->{$file}->{PATH};
        
        info($requests_data->{$file}->{TEXT}) if($requests_data->{$file}->{TEXT});
        my $request = buildRequest($request_url, $method, 0, 0);
        my $response = $browser->request($request);
        displayResponse($response) if($debug);
        
        foreach my $regex_type (keys %{ $regexes_data }) {
            foreach my $regex (@{ $regexes_data->{$regex_type} }) {
                if($response->content =~ /$regex/i) {
                    if($regex_type eq "VERSIONS") {
                        my ($match) = $response->content =~ /$regex/i;
                        $results->{versions} = $match if($match);
                    } else {
                        my @matches = $response->content =~ m/$regex/sgi;
                        push(@{ $results->{lc($regex_type)} }, @matches) if(0+@matches);
                    }
                }
            }
        }
    }
    
    return $results;
}

sub hash_files_fingerprint {
    my ( $browser, $requests_data, $url ) = @_;
    my $versions = 0;
    
    my @no_existing_directories = ();
    
    foreach my $directory (sort keys %{ $requests_data }) {
        next if(in_array($directory, @no_existing_directories));
        
        my $request_url = $url . $directory;
        info("Checking if directory: " . color("cyan") . $directory . color("blue") . " on: " . color("cyan") . $url) if($verbose || $debug);
        my $request = buildRequest($request_url, 'GET', 0, 0);
        my $response = $browser->request($request);
        displayResponse($response) if($debug);
        
        if($response->is_success) {
            result("Directory found: " . $response->request->uri);
            
            foreach my $path (sort keys %{ $requests_data->{$directory} }) {
                $request_url = $url . $requests_data->{$directory}->{$path}->{PATH};
                my $method = $requests_data->{$directory}->{$path}->{METHOD};
            
                info($requests_data->{$directory}->{$path}->{TEXT}) if($verbose || $debug);
                my $request = buildRequest($request_url, $method, 0, 0);
                my $response = $browser->request($request);
                displayResponse($response) if($debug);
                
                if($response->is_success) {
                    my $response_hash = md5_hex($response->content);
                    result("File found: " . $response->request->uri . color("blue") . " | Hash: " . color("yellow") . $response_hash);
                    
                    if(defined($requests_data->{$directory}->{$path}->{HASHES}->{$response_hash})) {
                        $versions = join(',', @{ $requests_data->{$directory}->{$path}->{HASHES}->{$response_hash} });
                        return $versions;
                    } else {
                        warning("Any hash match for file: " . color("cyan") . $path . color("blue") . " and hash: " . color("cyan") . $response_hash);
                    }
                }
            }
        } else {
            push(@no_existing_directories, $directory);
        }
    }
}

sub uniq {
    my ( @array ) = @_;
    
    return keys { map { $_ => 1 } @array };
}

sub in_array {
    my ( $value, @array ) = @_;
    my $in = 0;
    
    if ( grep { $value eq $_ } @array ) {
        $in = 1;
        return $in;
    } else {
        $in = 0;
    }
    
    return $in;
}

sub read_file {
    my ($file, $chomp) = @_;
    $chomp = 0 if(!defined($chomp));
    
    my @final_content = ();
    
    open FILE, $file or die error("Couldn't read: $file (" . $@ . ")");
    my @content = <FILE>;
    close FILE;
    
    if($chomp) {
        foreach my $line (@content) {
            chomp $line;
            push(@final_content, $line);
        }
    } else {
        @final_content = @content;   
    }
    
    return @final_content;
}

sub write_file {
    my ( $file, @content ) = @_;
    
    open FILE, ">", $file or die error("Couldn't open: $file (" . $@ . ")");
    
    foreach my $line (@content) {
        print FILE $line if($line);
    }
    
    close FILE;
}

sub displayResponse {
    my ( $response ) = @_;
    my $request = $response->request;
    
    ### Request
    print "\n\n" . color("yellow") . "--> " . color("blue") .  uc($request->method) . color("cyan") . ' ' . $request->uri->path . color("white") . " HTTP/1.1\n";
    print color("yellow") . "--> "  . color("white") . "Host: " .  color("cyan") . $request->uri->host . "\n";
    
    foreach my $header_name (keys %{ $request->headers }) {
        next if(reftype($request->header($header_name)));
        print color("yellow") . "--> "  . color("white") . $header_name . ": " . color("cyan") . $request->header($header_name) . "\n";
    }
    
    if($request->content) {
        print color("yellow") . "--> "  . color("white") . $request->content . "\n";
    }
    print "\n\n";
    
    
    ### Response
    print color("green") . "<-- "  . color("white") . "HTTP/1.1 " . color("cyan") . $response->status_line . "\n";
    
    foreach my $header_name (keys %{ $response->headers }) {
        next if(reftype($response->header($header_name)));
        print color("green") . "<-- "  . color("white") . $header_name . ": " . color("cyan") . $response->header($header_name) . "\n";
    }
    print "\n" . color("white") . $response->decoded_content . "\n";
}

sub info {
    my ( $text ) = @_;
    print color("white") . "[" . color("blue") . "*" . color("white") . "]" . color("blue") . " INFO" . color("white") . ": " . color("blue") . " $text\n";
}

sub warning {
    my ( $text ) = @_;
    print color("white") . "[" . color("yellow") . "!" . color("white") . "]" . color("yellow") . " WARNING" . color("white") . ": " . color("blue") . "$text\n";
}

sub result {
    my ( $text ) = @_;
    print color("white") . '[' . color("green") . '+' . color("white") . ']' . color("green") . " SUCCESS" . color("white") . ':' . color("blue") . " $text\n\n";
}

sub error {
    my ( $text ) = @_;
    print color("white") . "[" . color("red") . "-" . color("white") . "]" . color("red") . " ERROR" . color("white") . ": " . color("blue") . "$text\n";
    exit;
}
