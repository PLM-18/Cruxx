import logo from '../../../../assets/Logo_Cruxx.png'
const links = [
    {"name":"Workspaces","url":"workspaces"},
]

export default function Header(){
    return(
        <div className="w-full px-8 flex justify-between items-center">
            <div className="icon-container w-38 flex justify-center">
                <img src={logo} className="h-17 " alt="React logo" />
            </div>
            <div className="links flex justify-between w-fit">
                {
                    links.map(link=>(
                        <a className='mx-4' href={link.url}>{link.name}</a>
                    ))
                }
            </div>
            <div className="buttons-container w-38 flex">
                <div className="buttons">theme</div>
                <div className="buttons">Get in touch</div>
            </div>
        </div>
    )
}