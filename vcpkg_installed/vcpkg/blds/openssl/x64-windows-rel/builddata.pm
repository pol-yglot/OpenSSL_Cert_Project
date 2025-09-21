package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    @PREFIX
    @libdir
    @BINDIR @BINDIR_REL_PREFIX
    @LIBDIR @LIBDIR_REL_PREFIX
    @INCLUDEDIR @INCLUDEDIR_REL_PREFIX
    @APPLINKDIR @APPLINKDIR_REL_PREFIX
    @ENGINESDIR @ENGINESDIR_REL_LIBDIR
    @MODULESDIR @MODULESDIR_REL_LIBDIR
    @PKGCONFIGDIR @PKGCONFIGDIR_REL_LIBDIR
    @CMAKECONFIGDIR @CMAKECONFIGDIR_REL_LIBDIR
    $VERSION @LDLIBS
);

our @PREFIX                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel' );
our @libdir                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel' );
our @BINDIR                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel\apps' );
our @BINDIR_REL_PREFIX          = ( 'apps' );
our @LIBDIR                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel' );
our @LIBDIR_REL_PREFIX          = ( '' );
our @INCLUDEDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel\include', 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel\include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include', './include' );
our @APPLINKDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel\ms' );
our @APPLINKDIR_REL_PREFIX      = ( 'ms' );
our @ENGINESDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel\engines' );
our @ENGINESDIR_REL_LIBDIR      = ( 'engines' );
our @MODULESDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel\providers' );
our @MODULESDIR_REL_LIBDIR      = ( 'providers' );
our @PKGCONFIGDIR               = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '.' );
our @CMAKECONFIGDIR             = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\blds\openssl\x64-windows-rel' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( '.' );
our $VERSION                    = '3.5.3';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ')
    : split(/ +/, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ');

1;
