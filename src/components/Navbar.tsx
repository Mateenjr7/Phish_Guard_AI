import { Shield } from "lucide-react";
import { SignInButton, SignedIn, SignedOut, UserButton } from "@clerk/clerk-react";

const Navbar = () => {
  return (
    <header className="w-full fixed top-0 left-0 z-50 bg-background/80 backdrop-blur border-b">
      <div className="max-w-7xl mx-auto flex items-center justify-between px-6 py-4">

        {/* Logo */}
        <div className="flex items-center gap-2 font-bold text-lg">
          <Shield className="w-5 h-5 text-primary" />
          PhishGuard
        </div>

        {/* Right side auth */}
        <div>
          <SignedOut>
            <SignInButton>
              <button className="px-4 py-2 bg-primary text-white rounded-md font-semibold">
                Sign In
              </button>
            </SignInButton>
          </SignedOut>

          <SignedIn>
            <UserButton afterSignOutUrl="/" />
          </SignedIn>
        </div>

      </div>
    </header>
  );
};

export default Navbar;