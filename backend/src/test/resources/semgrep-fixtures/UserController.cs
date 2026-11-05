using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;

public class UserController : Controller
{
    public object Get(string id, SqlConnection conn)
    {
        // codelens-expect: SQL_INJECTION
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);
        var ok = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
        // codelens-expect: COMMAND_INJECTION
        Process.Start("cmd.exe", "/c ping " + id);
        Process.Start("notepad.exe", id);
        // codelens-expect: INSECURE_DESERIALIZATION
        var f = new BinaryFormatter();
        // codelens-expect: SWALLOWED_EXCEPTION
        try
        {
            cmd.ExecuteNonQuery();
        }
        catch (Exception e) { }
        return ok;
    }

    public string Bio(string bio)
    {
        // codelens-expect: UNSAFE_HTML
        return Html.Raw(bio).ToString();
    }

    public void Configure(IApplicationBuilder app)
    {
        // codelens-expect: PERMISSIVE_CORS
        app.UseCors(p => p.AllowAnyOrigin());
        var handler = new HttpClientHandler();
        // codelens-expect: TLS_VERIFY_DISABLED
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
    }
}
