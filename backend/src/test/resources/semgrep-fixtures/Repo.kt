import java.sql.Connection

class Repo(private val conn: Connection) {
    fun find(name: String) {
        val st = conn.createStatement()
        // codelens-expect: SQL_INJECTION
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
        val ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
        // codelens-expect: SWALLOWED_EXCEPTION
        try {
            ps.execute()
        } catch (e: Exception) {
        }
    }
}

fun Application.module() {
    install(CORS) {
        // codelens-expect: PERMISSIVE_CORS
        anyHost()
    }
}
