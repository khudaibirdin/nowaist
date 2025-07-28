package usecases

import (
	"app/internal/config"
	"app/internal/entities"
	pb "app/pkg/api/grpc_service"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/api/sheets/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SavingUseCase struct {
	Logger        zerolog.Logger
	Config        *config.Config
	SheetsService *sheets.Service
}

func NewSavingUseCase(logger zerolog.Logger, cfg *config.Config) *SavingUseCase {
	return &SavingUseCase{
		Logger: logger,
		Config: cfg,
	}
}

func (uc *SavingUseCase) Create(userID int64, savingGroup entities.SavingGroup) error {
	conn, err := grpc.NewClient(uc.Config.DataProviderURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		uc.Logger.Error().Err(err).Msg("did not connect")
	}
	defer conn.Close()
	client := pb.NewWaistServiceClient(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var Request pb.SetWaistsRequest
	for _, savings := range savingGroup.Savings {
		Request.Waists = append(
			Request.Waists,
			&pb.Waist{
				GroupName: savings.GroupName,
				Value:     savings.Value,
			},
		)
	}
	Request.DateCreated = timestamppb.New(savingGroup.DateCreate)
	Request.UserId = userID
	_, err = client.SetWaists(ctx, &Request)
	return err
}

func (uc *SavingUseCase) GetAll() ([]entities.Saving, error) {
	return []entities.Saving{}, nil
}

func (uc *SavingUseCase) GetLastSummarized(userID int64, amount int64) ([]entities.SavingsSummarized, error) {
	conn, err := grpc.NewClient(uc.Config.DataProviderURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		uc.Logger.Error().Err(err).Msg("did not connect")
	}
	defer conn.Close()
	client := pb.NewWaistServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	Request := &pb.GetLastWaistsRequest{Amount: amount, UserId: userID}
	data, err := client.GetLastWaists(ctx, Request)
	fmt.Println(data)
	response := []entities.SavingsSummarized{}
	for _, waists := range data.Waists {
		summarized := int64(0)
		for _, waist := range waists.Waists {
			summarized = summarized + waist.Value
		}
		response = append(response, entities.SavingsSummarized{Value: summarized, DateCreate: waists.DateCreated.AsTime().String()})
	}
	return response, nil
}
