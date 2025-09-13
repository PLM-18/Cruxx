import './styles/App.css'
import Header from './components/header'
import { Route, Routes } from 'react-router-dom'
import Landing from './pages/landing'
import Login from './pages/login'
import Signup from './pages/signup'

function App() {

  return (
    <div className="bg-background min-h-screen w-full flex flex-col ">

      <Header />
      <main className='flex-1 w-full flex flex-col'>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/register" element={<Signup />} />
        </Routes>
      </main>
    </div>
  )
}
export default App
