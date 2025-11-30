import { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await fetch('/api/me', { credentials: 'same-origin' });
      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    const response = await fetch('/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email, password }),
    });

    if (response.redirected || response.ok) {
      await checkAuth();
      return { success: true };
    }

    return { success: false, error: 'Invalid email or password' };
  };

  const signup = async (email, firstName, password1, password2) => {
    const response = await fetch('/sign-up', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email, firstName, password1, password2 }),
    });

    if (response.redirected || response.ok) {
      await checkAuth();
      return { success: true };
    }

    return { success: false, error: 'Signup failed. Email may already be registered.' };
  };

  const logout = async () => {
    await fetch('/logout', { credentials: 'same-origin' });
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
