// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    internal sealed class SafeFreeNegoCredentials : SafeFreeCredentials
    {
        private SafeGssCredHandle _credential;

        public SafeGssCredHandle GssCredential
        {
            get { return _credential; }
        }

        public SafeFreeNegoCredentials(string username, string password, string domain) : base(IntPtr.Zero, true)
        {
            bool ignore = false;
            _credential = SafeGssCredHandle.Create(username, password, domain);
            _credential.DangerousAddRef(ref ignore);
        }

        public override bool IsInvalid
        {
            get { return (null == _credential); }
        }

        protected override bool ReleaseHandle()
        {
            _credential.DangerousRelease();
            _credential = null;
            return true;
        }
    }

    internal sealed class SafeDeleteNegoContext : SafeDeleteContext
    {
        private SafeGssNameHandle _targetName;
        private SafeGssContextHandle _context;

        public SafeGssNameHandle TargetName
        {
            get { return _targetName; }
        }

        public SafeGssContextHandle GssContext
        {
            get { return _context; }
        }

        public SafeDeleteNegoContext(SafeFreeNegoCredentials credential, string targetName)
            : base(credential)
        {
            try
            {
                _targetName = SafeGssNameHandle.CreatePrincipal(targetName);
            }
            catch
            {
                Debug.Assert((null != credential), "Null credential in SafeDeleteNegoContext");
                credential.DangerousRelease();
                credential = null;
                throw;
            }
        }

        public void SetGssContext(SafeGssContextHandle context)
        {
            Debug.Assert(!context.IsInvalid, "Invalid context passed to SafeDeleteNegoContext");
            _context = context;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (null != _context)
                {
                    _context.Dispose();
                    _context = null;
                }

                if (_targetName != null)
                {
                    _targetName.Dispose();
                    _targetName = null;
                }
            }
            base.Dispose(disposing);
        }
    }
}
