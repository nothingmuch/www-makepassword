package WWW::MakePassword;
use Moose;

with qw(MooseX::Getopt::Dashes);

use MooseX::Types::Moose qw(Str Bool);
use MooseX::Types::Path::Class qw(File);
use MooseX::Types::Authen::Passphrase qw(Passphrase);

use Digest::HMAC_SHA1 qw(hmac_sha1);
use MIME::Base64 qw(encode_base64);
use Term::ReadPassword;
use File::HomeDir;
use Path::Class qw(dir);
use YAML::XS qw(LoadFile DumpFile);
use Clipboard;

use autodie qw(rename LoadFile DumpFile);

use namespace::clean -except => 'meta';

has [qw(save copy)] => (
	isa => Bool,
	is  => "ro",
	default => 0,
);

has login => (
	isa => Str,
	is  => "ro",
	lazy_build => 1,
);

sub _build_login {
	my $self = shift;

	my $conf = $self->configuration->{$self->site};

	if ( $conf ) {
		my @logins = sort keys %$conf;
		if ( @logins == 1 ) {
			return $logins[0];
		} else {
			local $" = ", ";
			die "Multiple logins found for " . $self->site . ", please specify one (@logins)\n";
		}
	} else {
		return $ENV{USER};
	}
}

has site => (
	isa => Str,
	is  => "ro",
	required => 1,
);

has password => (
	isa     => Str,
	is      => "ro",
	lazy_build => 1,
);

sub _build_password {
	my $self = shift;

	my $p = $self->saved_password;

	if ( $p->isa("Authen::Passphrase::Clear") ) {
		return $p->passphrase;
	} else {
		return $self->prompt_password;
	}
}

has digest => (
	traits => [qw(NoGetopt)],
	isa => Str,
	is  => "ro",
	lazy_build => 1,
);

sub _build_digest {
	my $self = shift;

	return hmac_sha1(
		join("\0", $self->login, $self->site),
		$self->password,
	);
}

has saved_password_file => (
	isa => File,
	is  => "ro",
	coerce => 1,
	lazy_build => 1,
);

sub _build_saved_password_file {
	dir(File::HomeDir->my_home)->file(".wpasswd")
}

has saved_password => (
	isa => Passphrase,
	is  => "ro",
	coerce => 1,
	lazy_build => 1,
);

sub _build_saved_password {
	my $self = shift;

	if ( $self->saved_password_file ) {
		my $p = $self->saved_password_file->slurp;
		chomp $p;
		return Authen::Passphrase->from_rfc2307($p);
	} else {
		require Authen::Passphrase::AcceptAll;
		return Authen::Passphrase::AcceptAll->new;
	}
}

has configuration_file => (
	isa => File,
	is  => "ro",
	coerce => 1,
	lazy_build => 1,
);

sub _build_configuration_file {
	dir(File::HomeDir->my_home)->file(".wpasswd.yml")
}

has configuration => (
	traits => [qw(NoGetopt)],
	isa => "HashRef",
	is  => "ro",
	lazy_build => 1,
);

sub _build_configuration {
	my $self = shift;

	if ( -f $self->configuration_file ) {
		return LoadFile($self->configuration_file->stringify);
	} else {
		return {};
	}
}

has site_configuration => (
	traits => [qw(NoGetopt)],
	isa => "HashRef",
	is  => "ro",
	lazy_build => 1,
);

sub _build_site_configuration {
	my $self = shift;

	$self->configuration->{$self->site}{$self->login} ||= {};
}

sub site_is_configured {
	my $self = shift;

	return 1 if $self->login ne $ENV{USER};
	return scalar keys %{ $self->site_configuration };

	return;
}

has truncate => (
	isa => "Int",
	is  => "ro",
	predicate => "has_truncate",
	lazy_build => 1,
);

sub _build_truncate {
	my $self = shift;

	$self->site_configuration->{truncate} || 0; # Maybe[Int] doesn't like Getopt
}

has encoded_password => (
	traits => [qw(NoGetopt)],
	isa => "Str",
	is  => "ro",
	lazy_build => 1,
);

sub _build_encoded_password {
	my $self = shift;

	my $encoded = encode_base64($self->digest);
	chomp $encoded;

	if ( $self->truncate ) {
		$encoded = substr($encoded, 0, $self->truncate);
	}

	return $encoded;
}

sub prompt_password {
	read_password('Password: ');
}

sub run {
	my $self = shift;

	$self->login;
	$self->verify_password;
	$self->output_digest;
	$self->save_configuration if $self->save;
}

sub verify_password {
	my $self = shift;

	unless ( $self->saved_password->match($self->password) ) {
		die("Incorrect password\n");
	}
}

sub output_digest {
	my $self = shift;

	my $encoded = $self->encoded_password;

	if ( $self->copy ) {
		Clipboard->copy($encoded);
	} else {
		local $\ = "\n";
		print $encoded;
	}
}

sub save_configuration {
	my $self = shift;

	$self->site_configuration;

	if ( $self->truncate ) {
		$self->site_configuration->{truncate} = $self->truncate;
	} else {
		delete $self->site_configuration->{truncate};
	}

	unless ( $self->site_is_configured ) {
		delete $self->configuration->{$self->site}{$self->login};

		unless ( scalar keys %{ delete $self->configuration->{$self->site} } ) {
			delete $self->configuration->{$self->site};
		}
	}

	rename( $self->configuration_file, $self->configuration_file . "~");
	DumpFile($self->configuration_file, $self->configuration);
}

__PACKAGE__->meta->make_immutable;

__PACKAGE__

__END__

=pod

=head1 NAME

WWW::MakePassword - Generate passwords for websites using an HMAC

=head1 SYNOPSIS

	# copy to clipboard
	wpasswd --copy --site foo.com

	# use special options and save them in ~/.wpasswd.yml
	# (future invocations with --site foo.com will DWIM)
	wpasswd --login foo --site bar.com --truncate 8 --save

=head1 DESCRIPTION

This module implements a command utility that creates per website addresses
from a single master password deterministically using L<Digest::HMAC>.

=head1 ATTRIBUTES

=over 4

=item password

The master password to seed L<Digest::HMAC> with.

If not specified will be prompted for (unless C<~/.wpasswd> exists *and* it's
C<{CLEARTEXT}>).

=item login

The login string.

Defaults to C<$ENV{USER}>.

Used to seed the HMAC and not much more.

=item copy

If set L<Clipboard> is used to copy the password instead of printing to STDOUT.

=item truncate

Truncate the output string to this many characters.

Available for brain damaged websites which enforce a maximum length on
passwords.

=item save

If true, the F<~/.wpasswd.yml> file will be updated with parameters from the
command line.

=back

=head1 CONFIGUARTION

=over 4

=item F<~/.wpasswd>

If this file contains an RFC 2307 formatted password, it will be used to verify
the password entered in the prompt.

If this happens to be a C<{CLEARTEXT}> password, then the password prompt will
be skipped entirely.

This is useful for making sure you enter the correct password when generating a
new string.

=item F<~/.wpasswd.yml>

This is a hash keyed by C<site> and then C<login> that contains per website
parameters.

It's kept up to date when C<save> is specified.

The only value currently saved is C<truncate> but in the future additional
encoding schemes will be added.

=back


