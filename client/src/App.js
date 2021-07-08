import React from 'react'
import {BrowserRouter as Router} from 'react-router-dom'
import 'materialize-css'
import {useAuth} from "./hooks/auth.hook"
import  {useRoutes} from "./routes"
import {Navbar} from "./components/Navbar"
import {AuthContext} from "./context/AuthContext"
import {Loader} from "./components/Loader"


function App() {
    const {token, login, logout, userId, ready} = useAuth()
    const isAuthenticated = !!token
    const routes = useRoutes(isAuthenticated)

    if (!ready) {
        return <Loader />
    }

  return (
      <AuthContext.Provider value={{token, login, logout, userId, isAuthenticated}}>
      <Router>
          { isAuthenticated && <Navbar/>}
          <div className="container">
             { routes }
          </div>
      </Router>
      </AuthContext.Provider>
  )
}

export default App
