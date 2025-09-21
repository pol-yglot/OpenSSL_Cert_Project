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

our @PREFIX                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows' );
our @libdir                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\lib' );
our @BINDIR                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\bin' );
our @BINDIR_REL_PREFIX          = ( 'bin' );
our @LIBDIR                     = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\lib' );
our @LIBDIR_REL_PREFIX          = ( 'lib' );
our @INCLUDEDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include' );
our @APPLINKDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\include\openssl' );
our @APPLINKDIR_REL_PREFIX      = ( 'include/openssl' );
our @ENGINESDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\lib\engines-3' );
our @ENGINESDIR_REL_LIBDIR      = ( 'engines-3' );
our @MODULESDIR                 = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\bin' );
our @MODULESDIR_REL_LIBDIR      = ( '..\bin' );
our @PKGCONFIGDIR               = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\lib' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '' );
our @CMAKECONFIGDIR             = ( 'D:\openSSLTest\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\share\openssl' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( '..\share\openssl' );
our $VERSION                    = '3.5.3';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ')
    : split(/ +/, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ');

1;
