import React, { useContext } from 'react'
import { NavLink, useHistory } from 'react-router-dom'
import { AuthContext } from '../context/AuthContext'

const Navbar = () => {
    const history = useHistory()
    const auth = useContext(AuthContext)

    const logoutHandler = event => {
        event.preventDefault()
        auth.logout()
        history.push('/')
    }
    return (
        <nav>
            <div class="nav-wrapper blue darken-1" style={{ padding: '0 2rem' }}>
            <span class="brand-logo">Сокращение ссылок</span>
            <ul id="nav-mobile" class="right hide-on-med-and-down">
                <li><NavLink to="/create">Создать</NavLink></li>
                <li><NavLink to="/links">Ссылки</NavLink></li>
                <li><a href="/" onClick={logoutHandler}>Выйти</a></li>
            </ul>
            </div>
        </nav>
    )
}

export default Navbar