using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;

namespace LibSsh2.Native
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public static class Functions
    {
        static Functions()
        {
            if (Environment.OSVersion.Platform != PlatformID.Unix)
                BootstrapWindows();
        }

        #region Windows bootstrapping
        private static void BootstrapWindows()
        {
            var thisAssemblyPath = new Uri(typeof(Functions).Assembly.CodeBase).LocalPath;
            var thisAssemblyFolder = Path.GetDirectoryName(thisAssemblyPath);

            var is64 = IntPtr.Size == 8;
            var platformFolder = is64 ? "x64" : "x86";

            // ReSharper disable once AssignNullToNotNullAttribute
            var dllDirectoryPath = Path.Combine(thisAssemblyFolder, "libssh2", platformFolder);
            var vcruntimePath = Path.Combine(dllDirectoryPath, "vcruntime140.dll");
            var libssh2Path = Path.Combine(dllDirectoryPath, "libssh2.dll");
            var zlib1Path = Path.Combine(dllDirectoryPath, "zlib1.dll");

            // First load C runtime
            var result = LoadLibrary(vcruntimePath);
            if (result == IntPtr.Zero)
                throw new ApplicationException($"Failed to load vcruntime140.dll, error: {Marshal.GetLastWin32Error()}");

            // Then load zlib1.dll
            result = LoadLibrary(zlib1Path);
            if (result == IntPtr.Zero)
                throw new ApplicationException($"Failed to load zlib1.dll, error: {Marshal.GetLastWin32Error()}");

            // And lastly libssh2.dll
            result = LoadLibrary(libssh2Path);
            if (result == IntPtr.Zero)
                throw new ApplicationException($"Failed to load libssh2.dll, error: {Marshal.GetLastWin32Error()}");
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string dllToLoad);
        #endregion

        #region libssh2.dll (version 1.8.0.0)
        public const int LIBSSH2_INIT_NO_CRYPTO = 0x0001;

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_init([MarshalAs(UnmanagedType.I4)] int flags);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void libssh2_exit();

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr libssh2_session_init_ex(IntPtr alloc_func, IntPtr free_func, IntPtr realloc_func, IntPtr @abstract);

        public static IntPtr libssh2_session_init() => libssh2_session_init_ex(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void libssh2_session_set_blocking(IntPtr session, int blocking);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_get_blocking(IntPtr session);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_handshake(IntPtr session, int sock);

        public const int LIBSSH2_SESSION_BLOCK_INBOUND = 0x0001;
        public const int LIBSSH2_SESSION_BLOCK_OUTBOUND = 0x0002;

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_block_directions(IntPtr session);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_flag(IntPtr session, int flag, int value);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_banner_set(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr)] string banner);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_banner_set(IntPtr session,
                                                    [MarshalAs(UnmanagedType.LPStr)] string banner);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_banner_get(IntPtr session);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void libssh2_trace(IntPtr session, int bitmask);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr libssh2_channel_open_ex(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr)] string channel_type,
                                                            uint channel_type_len,
                                                            uint window_size,
                                                            uint packet_size,
                                                            [MarshalAs(UnmanagedType.LPStr)] string message,
                                                            uint message_len);

        public const int LIBSSH2_CHANNEL_WINDOW_DEFAULT = 2 * 1024 * 1024;
        public const int LIBSSH2_CHANNEL_PACKET_DEFAULT = 32768;
        public const int LIBSSH2_CHANNEL_MINADJUST = 1024;

        public static IntPtr libssh2_channel_open_session(IntPtr session)
        {
            const string channelType = "session";
            return libssh2_channel_open_ex(session, channelType, (uint)channelType.Length, LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, null, 0);
        }

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_last_error(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr), Out] out string errmsg,
                                                            out int errmsg_len,
                                                            int want_buf = 1 /* don't set to 0 - let the CLR manage the errmsg buffer! */);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_last_errno(IntPtr session);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_set_last_error(IntPtr session,
                                                                int errcode,
                                                                [MarshalAs(UnmanagedType.LPStr)] string errmsg);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_process_startup(IntPtr channel,
                                                                 [MarshalAs(UnmanagedType.LPStr)] string request,
                                                                 uint request_len,
                                                                 [MarshalAs(UnmanagedType.LPStr)] string message,
                                                                 uint message_len);

        public static int libssh2_channel_shell(IntPtr channel)
        {
            const string request = "shell";
            return libssh2_channel_process_startup(channel, request, (uint)request.Length, null, 0);
        }

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_read_ex(IntPtr channel,
                                                         int stream_id,
                                                         [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In, Out] byte[] buf,
                                                         UIntPtr buflen);

        public static int libssh2_channel_read(IntPtr channel,
                                               byte[] buf)
        {
            return libssh2_channel_read_ex(channel, 0, buf, new UIntPtr((uint)buf.Length));
        }

        public const int SSH_EXTENDED_DATA_STDERR = 1;

        public static int libssh2_channel_read_stderr(IntPtr channel,
                                                      byte[] buf)
        {
            return libssh2_channel_read_ex(channel, SSH_EXTENDED_DATA_STDERR, buf, new UIntPtr((uint)buf.Length));
        }


        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_request_pty_ex(IntPtr channel,
                                                                [MarshalAs(UnmanagedType.LPStr)] string term,
                                                                uint term_len,
                                                                [MarshalAs(UnmanagedType.LPStr)] string modes,
                                                                uint modes_len,
                                                                int width,
                                                                int height,
                                                                int width_px,
                                                                int height_px);

        public const int LIBSSH2_TERM_WIDTH = 80;
        public const int LIBSSH2_TERM_HEIGHT = 24;
        public const int LIBSSH2_TERM_WIDTH_PX = 0;
        public const int LIBSSH2_TERM_HEIGHT_PX = 0;

        public static int libssh2_channel_request_pty(IntPtr channel, string term)
        {
            return libssh2_channel_request_pty_ex(channel, term, (uint)term.Length, null, 0,
                                                  LIBSSH2_TERM_WIDTH, LIBSSH2_TERM_HEIGHT,
                                                  LIBSSH2_TERM_WIDTH_PX, LIBSSH2_TERM_HEIGHT_PX);
        }

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_send_eof(IntPtr channel);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_eof(IntPtr channel);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_wait_eof(IntPtr channel);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_close(IntPtr channel);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_wait_closed(IntPtr channel);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_free(IntPtr channel);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_disconnect_ex(IntPtr session,
                                                               int reason,
                                                               [MarshalAs(UnmanagedType.LPStr)] string description,
                                                               [MarshalAs(UnmanagedType.LPStr)] string lang);


        public const int SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
        public const int SSH_DISCONNECT_PROTOCOL_ERROR = 2;
        public const int SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
        public const int SSH_DISCONNECT_RESERVED = 4;
        public const int SSH_DISCONNECT_MAC_ERROR = 5;
        public const int SSH_DISCONNECT_COMPRESSION_ERROR = 6;
        public const int SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
        public const int SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
        public const int SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
        public const int SSH_DISCONNECT_CONNECTION_LOST = 10;
        public const int SSH_DISCONNECT_BY_APPLICATION = 11;
        public const int SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
        public const int SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
        public const int SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
        public const int SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;

        public static int libssh2_session_disconnect(IntPtr session, string description)
        {
            return libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, description, "");
        }

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_free(IntPtr session);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_hostkey_hash(IntPtr session, int hash_type);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_hostkey(IntPtr session,
                                                            [Out] out UIntPtr len, [Out] out int type);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_method_pref(IntPtr session,
                                                             int method_type,
                                                             [MarshalAs(UnmanagedType.LPStr)] string prefs);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_methods(IntPtr session, int method_type);

        public const int LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA = -1;
        public const int LIBSSH2_CHANNEL_FLUSH_ALL = -2;

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_flush_ex(IntPtr channel, int streamid);

        public static int libssh2_channel_flush(IntPtr channel)
        {
            return libssh2_channel_flush_ex(channel, 0);
        }

        public static int libssh2_channel_flush_stderr(IntPtr channel)
        {
            return libssh2_channel_flush_ex(channel, SSH_EXTENDED_DATA_STDERR);
        }

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_write_ex(IntPtr channel,
                                                          int stream_id,
                                                          [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In] byte[] buf,
                                                          UIntPtr buflen);

        public static int libssh2_channel_write(IntPtr channel, byte[] buf)
        {
            return libssh2_channel_write_ex(channel, 0, buf, new UIntPtr((uint)buf.Length));
        }

        
        public static int libssh2_userauth_password(IntPtr session, string username, string password)
        {
            return libssh2_userauth_password_ex(session, username, (uint)username.Length, password, (uint)password.Length, IntPtr.Zero);
        }


        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_password_ex(IntPtr session,
                                                              [MarshalAs(UnmanagedType.LPStr)] string username,
                                                              uint username_len,
                                                              [MarshalAs(UnmanagedType.LPStr)] string password,
                                                              uint password_len,
                                                              IntPtr passwotd_change_cb);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_authenticated(IntPtr session);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey_fromfile_ex(IntPtr session,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                        uint username_len,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string passphrase);

        public static int libssh2_userauth_publickey_fromfile(IntPtr session,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string passphrase)
        {
            return libssh2_userauth_publickey_fromfile_ex(session, username, (uint) username.Length, publickey, privatekey, passphrase);
        }


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        // IntPtr sig must point to a byte array that has been allocated with malloc()!
        public delegate int LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC(IntPtr session, [Out] out IntPtr sig, [Out] out UIntPtr sig_len,
                                                          [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] data, UIntPtr data_len, [Out] out IntPtr @abstract);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr)] string username,
                                                            byte[] pubkeydata,
                                                            UIntPtr pubkeydata_len,
                                                            LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC sign_callback,
                                                            [Out] out IntPtr @abstract);

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_hostbased_fromfile_ex(IntPtr session,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                        uint username_len,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string passphrase,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string hostname,
                                                                        uint hostname_len,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string local_username,
                                                                        uint local_username_len);

        public static int libssh2_userauth_hostbased_fromfilex(IntPtr session,
                                                               [MarshalAs(UnmanagedType.LPStr)] string username,
                                                               [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                               [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                               [MarshalAs(UnmanagedType.LPStr)] string passphrase,
                                                               [MarshalAs(UnmanagedType.LPStr)] string hostname,
                                                               [MarshalAs(UnmanagedType.LPStr)] string local_username)
        {
            return libssh2_userauth_hostbased_fromfile_ex(session, username, (uint) username.Length, publickey, privatekey,
                                                          passphrase, hostname, (uint) hostname.Length, local_username,
                                                          (uint) local_username.Length);
        }

        [DllImport("libssh2.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey_frommemory(IntPtr session,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                       UIntPtr username_len,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string publickeyfiledata,
                                                                       UIntPtr publickeyfiledata_len,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string privatekeyfiledata,
                                                                       UIntPtr privatekeyfiledata_len,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string passphrase);

        // Error codes
        public const int LIBSSH2_ERROR_NONE = 0;
        public const int LIBSSH2_ERROR_SOCKET_NONE = -1;
        public const int LIBSSH2_ERROR_BANNER_RECV = -2;
        public const int LIBSSH2_ERROR_BANNER_SEND = -3;
        public const int LIBSSH2_ERROR_INVALID_MAC = -4;
        public const int LIBSSH2_ERROR_KEX_FAILURE = -5;
        public const int LIBSSH2_ERROR_ALLOC = -6;
        public const int LIBSSH2_ERROR_SOCKET_SEND = -7;
        public const int LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8;
        public const int LIBSSH2_ERROR_TIMEOUT = -9;
        public const int LIBSSH2_ERROR_HOSTKEY_INIT = -10;
        public const int LIBSSH2_ERROR_HOSTKEY_SIGN = -11;
        public const int LIBSSH2_ERROR_DECRYPT = -12;
        public const int LIBSSH2_ERROR_SOCKET_DISCONNECT = -13;
        public const int LIBSSH2_ERROR_PROTO = -14;
        public const int LIBSSH2_ERROR_PASSWORD_EXPIRED = -15;
        public const int LIBSSH2_ERROR_FILE = -16;
        public const int LIBSSH2_ERROR_METHOD_NONE = -17;
        public const int LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18;
        public const int LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
        public const int LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19;
        public const int LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20;
        public const int LIBSSH2_ERROR_CHANNEL_FAILURE = -21;
        public const int LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22;
        public const int LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23;
        public const int LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24;
        public const int LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25;
        public const int LIBSSH2_ERROR_CHANNEL_CLOSED = -26;
        public const int LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27;
        public const int LIBSSH2_ERROR_SCP_PROTOCOL = -28;
        public const int LIBSSH2_ERROR_ZLIB = -29;
        public const int LIBSSH2_ERROR_SOCKET_TIMEOUT = -30;
        public const int LIBSSH2_ERROR_SFTP_PROTOCOL = -31;
        public const int LIBSSH2_ERROR_REQUEST_DENIED = -32;
        public const int LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33;
        public const int LIBSSH2_ERROR_INVAL = -34;
        public const int LIBSSH2_ERROR_INVALID_POLL_TYPE = -35;
        public const int LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36;
        public const int LIBSSH2_ERROR_EAGAIN = -37;
        public const int LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38;
        public const int LIBSSH2_ERROR_BAD_USE = -39;
        public const int LIBSSH2_ERROR_COMPRESS = -40;
        public const int LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41;
        public const int LIBSSH2_ERROR_AGENT_PROTOCOL = -42;
        public const int LIBSSH2_ERROR_SOCKET_RECV = -43;
        public const int LIBSSH2_ERROR_ENCRYPT = -44;
        public const int LIBSSH2_ERROR_BAD_SOCKET = -45;
        public const int LIBSSH2_ERROR_KNOWN_HOSTS = -46;
        #endregion
    }
}
