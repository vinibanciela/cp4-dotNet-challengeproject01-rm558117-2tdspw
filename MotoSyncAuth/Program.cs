// Imports necessários
using System;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using MotoSyncAuth.Services;
using MotoSyncAuth.Models;
using MotoSyncAuth.DTOs;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;

const string UserNotFoundMessage = "Usuário não encontrado.";
const string RoleAdmin = "Administrador";
const string RoleManager = "Gerente";
const string RoleEmployee = "Funcionario";
const string RouteId = "/{id}";

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------
// REGISTRO DE SERVIÇOS
// -----------------------------------------------------------

// Swagger (documentação automática da API)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "Insira o token JWT no formato: Bearer {token}",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = JwtBearerDefaults.AuthenticationScheme
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = JwtBearerDefaults.AuthenticationScheme
                }
            },
            Array.Empty<string>() // evita alocação de array zero-length
        }
    });
});

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Rate Limiting
builder.Services.AddRateLimiter(opt =>
{
    opt.AddFixedWindowLimiter("default", options =>
    {
        options.Window = TimeSpan.FromSeconds(10);
        options.PermitLimit = 5;
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 2;
    });
});

// Serviços
builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<UserService>();

// Valida o segredo JWT para evitar null em Encoding.GetBytes
var jwtSecret = builder.Configuration["JwtSettings:Secret"];
if (string.IsNullOrWhiteSpace(jwtSecret))
{
    throw new InvalidOperationException("JwtSettings:Secret não está configurado.");
}

// Autenticação/Autorização
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// -----------------------------------------------------------
// MIDDLEWARES DO PIPELINE HTTP
// -----------------------------------------------------------

app.UseSwagger();
app.UseSwaggerUI();
app.UseCors("AllowAll");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// -----------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// -----------------------------------------------------------

var authGroup = app.MapGroup("/auth").WithTags("Autenticação");

authGroup.MapPost("/login", (LoginRequest request, UserService userService, JwtService jwt) =>
{
    var user = userService.ValidateUser(request.Email, request.Password);
    if (user == null)
        return Results.Unauthorized();

    var token = jwt.GenerateToken(user);
    return Results.Ok(new AuthResponse(user.Username, token));
})
.WithSummary("Login do usuário")
.WithDescription("Autentica o usuário e retorna um token JWT.")
.Produces<AuthResponse>(200)
.Produces(401)
.RequireRateLimiting("default");

authGroup.MapGet("/me", (HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    return Results.Ok(user);
})
.WithSummary("Dados do usuário logado")
.WithDescription("Retorna os dados do usuário a partir do token JWT.")
.Produces<User>(200)
.Produces(401);

authGroup.MapPost("/forgot-password", (ForgotPasswordRequest request, UserService userService) =>
{
    var result = userService.GeneratePasswordResetToken(request.Email);
    return result ? Results.Ok("Token de redefinição gerado com sucesso.") : Results.NotFound(UserNotFoundMessage);
})
.WithSummary("Solicitação de redefinição de senha")
.WithDescription("Gera um token de redefinição de senha para o e-mail informado.")
.Produces<string>(200)
.Produces(404);

authGroup.MapPost("/reset-password", (ResetPasswordRequest request, UserService userService) =>
{
    var result = userService.ResetPassword(request.Token, request.NewPassword);
    return result ? Results.Ok("Senha redefinida com sucesso.") : Results.BadRequest("Token inválido ou expirado.");
})
.WithSummary("Redefinir senha")
.WithDescription("Permite redefinir a senha com um token válido.")
.Produces<string>(200)
.Produces(400);

// -----------------------------------------------------------
// ROTAS DE GESTÃO DE USUÁRIOS
// -----------------------------------------------------------

var userGroup = app.MapGroup("/users").WithTags("Usuários");

userGroup.MapGet("/", (HttpContext http, UserService userService, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    var users = userService.GetAllUsers();

    if (user.Role?.Name == RoleAdmin)
    {
        var response = users.Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role?.Name ?? ""));
        return Results.Ok(response);
    }
    else if (user.Role?.Name == RoleManager)
    {
        users = users.Where(u => u.Role?.Name == RoleManager || u.Role?.Name == RoleEmployee);
        var response = users.Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role?.Name ?? ""));
        return Results.Ok(response);
    }
    else
    {
        return Results.Forbid();
    }
})
.WithSummary("Listar usuários")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários. Funcionário não vê ninguém.")
.Produces<IEnumerable<UserResponse>>(200)
.Produces(401)
.Produces(403);

userGroup.MapGet(RouteId, (int id, HttpContext http, UserService userService, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    var targetUser = userService.GetUserById(id);
    if (targetUser == null)
        return Results.NotFound(UserNotFoundMessage);

    if (user.Role?.Name == RoleAdmin)
    {
        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
        return Results.Ok(response);
    }
    else if (user.Role?.Name == RoleManager)
    {
        if (targetUser.Role?.Name == RoleAdmin)
            return Results.Forbid();

        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
        return Results.Ok(response);
    }
    else
    {
        return Results.Forbid();
    }
})
.WithSummary("Buscar usuário por ID")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários (não Admin). Funcionário não vê ninguém.")
.Produces<UserResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);

userGroup.MapGet("/by-email", (string email, HttpContext http, UserService userService, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    var targetUser = userService.GetUserByEmail(email);
    if (targetUser == null)
        return Results.NotFound(UserNotFoundMessage);

    if (user.Role?.Name == RoleAdmin)
    {
        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
        return Results.Ok(response);
    }
    else if (user.Role?.Name == RoleManager)
    {
        if (targetUser.Role?.Name == RoleAdmin)
            return Results.Forbid();

        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
        return Results.Ok(response);
    }
    else
    {
        return Results.Forbid();
    }
})
.WithSummary("Buscar usuário por e-mail")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários (não Admin). Funcionário não vê ninguém.")
.Produces<UserResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);

userGroup.MapPost("/", (CreateUserRequest request, HttpContext http, UserService userService, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name == RoleEmployee)
        return Results.Forbid();

    if (user.Role?.Name == RoleManager && request.RoleId != 3)
        return Results.Forbid();

    var newUser = userService.CreateUser(request);
    if (newUser == null)
        return Results.BadRequest("E-mail já cadastrado.");

    var response = new UserResponse(newUser.Id, newUser.Username, newUser.Email, newUser.Role?.Name ?? "");
    return Results.Created($"/users/{newUser.Id}", response);
})
.WithSummary("Criar usuário")
.WithDescription("Administrador pode criar qualquer cargo. Gerente apenas Funcionários.")
.Produces<UserResponse>(201)
.Produces(401)
.Produces(403)
.Produces(400);

userGroup.MapPut(RouteId, (int id, UpdateUserRequest request, HttpContext http, UserService userService, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name == RoleEmployee)
        return Results.Forbid();

    var targetUser = userService.GetUserById(id);
    if (targetUser == null)
        return Results.NotFound(UserNotFoundMessage);

    if (user.Role?.Name == RoleManager && targetUser.Role?.Name != RoleEmployee)
        return Results.Forbid();

    var success = userService.UpdateUser(id, request);
    return success ? Results.Ok("Usuário atualizado.") : Results.BadRequest("Falha ao atualizar.");
})
.WithSummary("Atualizar usuário")
.WithDescription("Administrador pode editar qualquer usuário. Gerente apenas Funcionários.")
.Produces<string>(200)
.Produces(400)
.Produces(401)
.Produces(403)
.Produces(404);

userGroup.MapDelete(RouteId, (int id, HttpContext http, UserService userService, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name == RoleEmployee)
        return Results.Forbid();

    var targetUser = userService.GetUserById(id);
    if (targetUser == null)
        return Results.NotFound(UserNotFoundMessage);

    if (user.Role?.Name == RoleManager && targetUser.Role?.Name != RoleEmployee)
        return Results.Forbid();

    var success = userService.DeleteUser(id);
    return success ? Results.Ok("Usuário excluído.") : Results.BadRequest("Erro ao excluir usuário.");
})
.WithSummary("Deletar usuário")
.WithDescription("Administrador pode excluir qualquer usuário. Gerente apenas Funcionários.")
.Produces<string>(200)
.Produces(400)
.Produces(401)
.Produces(403)
.Produces(404);

// -----------------------------------------------------------
// ROTAS DE GESTÃO DE CARGOS (ROLES)
// -----------------------------------------------------------

var roleGroup = app.MapGroup("/roles").WithTags("Cargos");

roleGroup.MapGet("/", (HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != RoleAdmin)
        return Results.Forbid();

    var roles = new List<RoleResponse>
    {
        new(1, RoleAdmin),
        new(2, RoleManager),
        new(3, RoleEmployee)
    };
    return Results.Ok(roles);
})
.WithSummary("Listar roles")
.WithDescription("Apenas Administrador pode acessar.")
.Produces<IEnumerable<RoleResponse>>(200)
.Produces(401)
.Produces(403);

roleGroup.MapGet(RouteId, (int id, HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != RoleAdmin)
        return Results.Forbid();

    var role = id switch
    {
        1 => new RoleResponse(1, RoleAdmin),
        2 => new RoleResponse(2, RoleManager),
        3 => new RoleResponse(3, RoleEmployee),
        _ => null
    };

    return role is not null ? Results.Ok(role) : Results.NotFound("Role não encontrada.");
})
.WithSummary("Buscar role por ID")
.WithDescription("Apenas Administrador pode consultar cargos.")
.Produces<RoleResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);

roleGroup.MapPut(RouteId, (int id, UpdateRoleRequest request, HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != RoleAdmin)
        return Results.Forbid();

    return id is >= 1 and <= 3
        ? Results.Ok($"Role {id} atualizada para: {request.Name}")
        : Results.NotFound("Role não encontrada.");
})
.WithSummary("Atualizar role")
.WithDescription("Apenas Administrador pode atualizar cargos.")
.Produces<string>(200)
.Produces(401)
.Produces(403)
.Produces(404);

roleGroup.MapDelete(RouteId, (int id, HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != RoleAdmin)
        return Results.Forbid();

    return id is >= 1 and <= 3
        ? Results.Ok($"Role {id} excluída com sucesso.")
        : Results.NotFound("Role não encontrada.");
})
.WithSummary("Excluir role")
.WithDescription("Apenas Administrador pode excluir cargos.")
.Produces<string>(200)
.Produces(401)
.Produces(403)
.Produces(404);

// ====== alteração para S6966 ======
await app.RunAsync();
