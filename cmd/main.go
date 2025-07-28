package main

import (
	"app/internal/config"
	"app/internal/entities"
	"app/internal/usecases"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pb "app/pkg/api/grpc_service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	config, err := config.New("./.env")
	if err != nil {
		logger.Panic().Err(err).Msg("Ошибка парсинга конфиг файла")
	}

	defaultRouter := chi.NewRouter()
	defaultRouter.Use(middleware.Logger)

	workDir, _ := os.Getwd()
	filesDir := http.Dir(filepath.Join(workDir, "static"))
	defaultRouter.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(filesDir)))
	defaultRouter.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(workDir, "static", "index.html"))
	})

	// Auth routes
	authRouter := chi.NewRouter()
	authRouterHandlerGroup := NewAuthRouterHandlerGroup(*config, logger)
	authRouter.Post("/login", authRouterHandlerGroup.Login)
	authRouter.Post("/register", authRouterHandlerGroup.Register)
	authRouter.Post("/verify", authRouterHandlerGroup.VerifyToken)
	defaultRouter.Mount("/auth", authRouter)

	savingsRouter := chi.NewRouter()
	savingUseCase := usecases.NewSavingUseCase(logger, config)
	SavingsRouterHandlerGroup := NewSavingsRouterHandlerGroup(*config, logger, savingUseCase)

	savingsRouter.Use(authRouterHandlerGroup.JWTMiddleware)
	savingsRouter.Post("/", SavingsRouterHandlerGroup.Create)
	savingsRouter.Get("/", SavingsRouterHandlerGroup.GetAll)
	savingsRouter.Get("/summarized", SavingsRouterHandlerGroup.GetLastSummarized)

	defaultRouter.Mount("/savings", savingsRouter)

	logger.Info().Msg("Запуск http сервера")
	http.ListenAndServe(fmt.Sprintf(":%s", config.HTTPPort), defaultRouter)
}

type SavingsRouterHandlerGroup struct {
	Logger        zerolog.Logger
	Config        config.Config
	SavingUseCase SavingUseCase
}

func NewSavingsRouterHandlerGroup(
	cfg config.Config,
	logger zerolog.Logger,
	savingUseCase SavingUseCase,
) *SavingsRouterHandlerGroup {
	return &SavingsRouterHandlerGroup{
		Config:        cfg,
		Logger:        logger,
		SavingUseCase: savingUseCase,
	}
}

type SavingUseCase interface {
	Create(userID int64, savings entities.SavingGroup) error
	GetAll() ([]entities.Saving, error)
	GetLastSummarized(userID int64, amount int64) ([]entities.SavingsSummarized, error)
}

func (router *SavingsRouterHandlerGroup) Create(w http.ResponseWriter, r *http.Request) {
	var saving entities.SavingGroup
	err := json.NewDecoder(r.Body).Decode(&saving)
	if err != nil {
		errDesc := "Ошибка парсинга json данных"
		router.Logger.Error().Msg(errDesc)
		w.WriteHeader(400)
		w.Write([]byte(errDesc))
		return
	}
	saving.FormatDate()
	userID := r.Context().Value("user_id").(int64)
	err = router.SavingUseCase.Create(userID, saving)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(201)
}

func (router *SavingsRouterHandlerGroup) GetAll(w http.ResponseWriter, r *http.Request) {
	data, err := router.SavingUseCase.GetAll()
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	n := len(data)
	needLen := 100
	start := 0
	if n > needLen {
		start = n - needLen
	}
	jsonData, err := json.Marshal(data[start:])
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write(jsonData)
}

func (router *SavingsRouterHandlerGroup) GetLastSummarized(w http.ResponseWriter, r *http.Request) {
	amount := 100
	userID := r.Context().Value("user_id").(int64)
	data, err := router.SavingUseCase.GetLastSummarized(userID, int64(amount))
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte(err.Error()))
		return
	}
	response := GetLastSummarizedResponse{
		Data: data,
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write(jsonResponse)
}

type GetLastSummarizedResponse struct {
	Data []entities.SavingsSummarized `json:"data"`
}

type AuthRouterHandlerGroup struct {
	Logger zerolog.Logger
	Config config.Config
}

func NewAuthRouterHandlerGroup(
	cfg config.Config,
	logger zerolog.Logger,
) *AuthRouterHandlerGroup {
	return &AuthRouterHandlerGroup{
		Config: cfg,
		Logger: logger,
	}
}

type LoginResponse struct {
	Token string `json:"token"`
}

type Claims struct {
	Username string `json:"username"`
	UserID   int64  `json:"user_id"`
	jwt.RegisteredClaims
}

func (router *AuthRouterHandlerGroup) Register(w http.ResponseWriter, r *http.Request) {
	var user entities.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		router.Logger.Error().Err(err).Msg("Ошибка парсинга запроса")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Неверный формат запроса"))
		return
	}
	conn, err := grpc.NewClient(router.Config.DataProviderURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		router.Logger.Error().Err(err).Msg("did not connect")
	}
	defer conn.Close()
	client := pb.NewWaistServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	userCreated, err := client.CreateUser(ctx, &pb.CreateUserRequest{Login: user.Login, Password: user.Password})
	if err != nil {
		router.Logger.Error().Err(err).Msg("error with CreateUser")
		return
	}
	if userCreated == nil {
		router.Logger.Error().Err(err).Msg("error with CreateUser, no user")
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Пользователь зарегистрирован"))
}

func (router *AuthRouterHandlerGroup) Login(w http.ResponseWriter, r *http.Request) {
	var req entities.User
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		router.Logger.Error().Err(err).Msg("Ошибка парсинга запроса")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Неверный формат запроса"))
		return
	}

	conn, err := grpc.NewClient(router.Config.DataProviderURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		router.Logger.Error().Err(err).Msg("did not connect")
	}
	defer conn.Close()
	client := pb.NewWaistServiceClient(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	user, err := client.GetUser(ctx, &pb.GetUserRequest{Login: req.Login})
	if err != nil {
		router.Logger.Error().Err(err).Msg("error with GetUser")
	}

	// Проверка логина и пароля (в реальном приложении нужно проверять хеш пароля из БД)
	if user == nil || req.Login != user.Login || req.Password != user.Password {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Неверный логин или пароль"))
		return
	}

	// Создаем JWT токен
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: req.Login,
		UserID:   user.Id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(router.Config.JWTSecret))
	if err != nil {
		router.Logger.Error().Err(err).Msg("Ошибка создания токена")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Ошибка создания токена"))
		return
	}

	response := LoginResponse{
		Token: tokenString,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		router.Logger.Error().Err(err).Msg("Ошибка сериализации ответа")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func (router *AuthRouterHandlerGroup) VerifyToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Токен не предоставлен"})
		return
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(router.Config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Недействительный токен"})
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Токен действителен"})
}

func (router *AuthRouterHandlerGroup) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Токен не предоставлен"))
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(router.Config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Недействительный токен"))
			return
		}

		// Добавляем user_id в контекст запроса
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)

		// Создаем новый запрос с обновленным контекстом
		r = r.WithContext(ctx)

		// Также можно добавить user_id в заголовки, если нужно
		r.Header.Set("X-User-ID", strconv.Itoa(int(claims.UserID)))

		next.ServeHTTP(w, r)
	})
}
