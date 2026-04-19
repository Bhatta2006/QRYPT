import React from 'react';
import ReactDOM from 'react-dom/client';
import { createBrowserRouter, RouterProvider, redirect } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { getAccessToken } from './lib/api';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import Admin from './pages/Admin';
import './index.css';

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').then((registration) => {
      console.log('SW registered: ', registration);
    }).catch((registrationError) => {
      console.log('SW registration failed: ', registrationError);
    });
  });
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const adminLoader = () => {
  const token = getAccessToken();
  if (!token) return redirect('/');
  
  try {
    const payloadIndex = token.split('.')[1];
    if (!payloadIndex) throw new Error();
    const payload = JSON.parse(atob(payloadIndex));
    // The requirement explicitly states to decode and check role === "admin"
    if (payload.role !== 'admin') {
      return redirect('/');
    }
  } catch (e) {
    return redirect('/');
  }
  return null;
};

const router = createBrowserRouter([
  { path: '/', element: <Dashboard /> },
  { path: '/scanner', element: <Scanner /> },
  { path: '/admin', element: <Admin />, loader: adminLoader },
]);

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>
);
