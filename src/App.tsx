import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { SignedIn, SignedOut, RedirectToSignIn } from "@clerk/clerk-react";

import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";

import Landing from "./pages/Landing";
import Index from "./pages/Index";        // Hero Section page
import SignInPage from "./pages/SignIn";
import SignUpPage from "./pages/SignUp";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />

      <BrowserRouter>
        <Routes>
          {/* Landing page */}
          <Route path="/" element={<Landing />} />

          {/* Protected Hero Section */}
          <Route
            path="/app"
            element={
              <SignedIn>
                <Index />
              </SignedIn>
            }
          />
          <Route
            path="/app"
            element={
              <SignedOut>
                <RedirectToSignIn />
              </SignedOut>
            }
          />

          {/* Authentication pages */}
          <Route path="/sign-in/*" element={<SignInPage />} />
          <Route path="/sign-up/*" element={<SignUpPage />} />

          {/* 404 fallback */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;