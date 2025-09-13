import logo from '../assets/react.svg'
const links = [
    {"name":"Workspaces","url":"#workspaces"},
]

export default function Header(){
    return(
        <div className="w-full px-8 flex justify-between items-center border border-red-600">
            <div className="icon-container w-38 border border-green-500 flex justify-center">
                <img src={logo} className="logo react" alt="React logo" />
            </div>
            <div className="links flex justify-between w-fit border border-amber-600">
                {
                    links.map(link=>(
                        <a className='mx-4' href={link.url}>{link.name}</a>
                    ))
                }
            </div>
            <div className="buttons-container w-38 flex border border-fuchsia-500">
                <div className="buttons">theme</div>
                <div className="buttons">Get in touch</div>
            </div>
        </div>
    )
}