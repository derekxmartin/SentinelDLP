import { BrowserRouter, Routes, Route } from 'react-router-dom'

function Dashboard() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-semibold mb-2">SentinelDLP</h1>
        <p className="text-slate-400">Data Loss Prevention Console</p>
        <div className="mt-8 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 border border-slate-700">
          <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-sm text-slate-300">System Online</span>
        </div>
      </div>
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
