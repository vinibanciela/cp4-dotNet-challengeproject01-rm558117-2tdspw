using MotoSyncAuth.Models;
using MotoSyncAuth.DTOs;
using System.Security.Cryptography;
using System.Text;

namespace MotoSyncAuth.Services;

public class UserService
{
    // Constantes para roles
    private const string RoleAdministrador = "Administrador";
    private const string RoleGerente = "Gerente";
    private const string RoleFuncionario = "Funcionario";

    // Lista em memória simulando um banco de dados de usuários
    private readonly List<User> _users = new()
    {
        new User
        {
            Id = 1,
            Username = "Admin",
            Email = "admin@mottu.com",
            PasswordHash = HashPassword("admin123"),
            Role = new Role { Id = 1, Name = RoleAdministrador }
        },
        new User
        {
            Id = 2,
            Username = RoleGerente,
            Email = "gerente@mottu.com",
            PasswordHash = HashPassword("gerente123"),
            Role = new Role { Id = 2, Name = RoleGerente }
        },
        new User
        {
            Id = 3,
            Username = RoleFuncionario,
            Email = "funcionario@mottu.com",
            PasswordHash = HashPassword("func123"),
            Role = new Role { Id = 3, Name = RoleFuncionario }
        }
    };

    private int _nextId = 4;

    // ------------------ Métodos para autenticação ------------------

    public User? ValidateUser(string email, string password)
    {
        var hash = HashPassword(password);
        var user = _users.FirstOrDefault(u =>
            u.Email.Equals(email, StringComparison.OrdinalIgnoreCase)
            && u.PasswordHash == hash);
        return user;
    }

    public bool GeneratePasswordResetToken(string email)
    {
        var user = _users.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        if (user == null) return false;

        user.PasswordResetToken = Guid.NewGuid().ToString();
        user.PasswordResetTokenExpiration = DateTime.UtcNow.AddMinutes(15);
        return true;
    }

    public bool ResetPassword(string token, string newPassword)
    {
        var user = _users.FirstOrDefault(u =>
            u.PasswordResetToken == token &&
            u.PasswordResetTokenExpiration.HasValue &&
            u.PasswordResetTokenExpiration > DateTime.UtcNow);

        if (user == null) return false;

        user.PasswordHash = HashPassword(newPassword);
        user.PasswordResetToken = null;
        user.PasswordResetTokenExpiration = null;
        return true;
    }

    // ------------------ CRUD de usuários (/users) ------------------

    public IEnumerable<User> GetAllUsers() => _users;

    public User? GetUserById(int id) => _users.FirstOrDefault(u => u.Id == id);

    public User? GetUserByEmail(string email) =>
        _users.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));

    public User? CreateUser(CreateUserRequest request)
    {
        if (_users.Any(u => u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase)))
            return null;

        string roleName;
        if (request.RoleId == 1)
            roleName = RoleAdministrador;
        else if (request.RoleId == 2)
            roleName = RoleGerente;
        else
            roleName = RoleFuncionario;

        var user = new User
        {
            Id = _nextId++,
            Username = request.Username,
            Email = request.Email,
            PasswordHash = HashPassword(request.Password),
            Role = new Role
            {
                Id = request.RoleId,
                Name = roleName
            }
        };

        _users.Add(user);
        return user;
    }
    public bool UpdateUser(int id, UpdateUserRequest request)
    {
        var user = GetUserById(id);
        if (user == null) return false;

        if (!string.IsNullOrWhiteSpace(request.Username))
            user.Username = request.Username;

        if (!string.IsNullOrWhiteSpace(request.Email))
            user.Email = request.Email;

        if (!string.IsNullOrWhiteSpace(request.Password))
            user.PasswordHash = HashPassword(request.Password);

        if (request.RoleId.HasValue)
        {
            string roleName;
            if (request.RoleId.Value == 1)
                roleName = RoleAdministrador;
            else if (request.RoleId.Value == 2)
                roleName = RoleGerente;
            else
                roleName = RoleFuncionario;

            user.Role = new Role
            {
                Id = request.RoleId.Value,
                Name = roleName
            };
        }

        return true;
    }


    public bool DeleteUser(int id)
    {
        var user = GetUserById(id);
        if (user == null) return false;
        _users.Remove(user);
        return true;
    }

    private static string HashPassword(string password)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }
}
