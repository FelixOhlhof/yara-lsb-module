#define STB_IMAGE_IMPLEMENTATION
#include "stb_image/stb_image.h"

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <yara/modules.h>

#define MODULE_NAME lsb

// Function to decode the message from image data
char* decode_message(char* host_data, int size, int* msg_size)
{
  // Convert to 1D (already in 1D in this case)
  int bits = 1 << ((host_data[0] & 48) >> 4);  // bits = 2 ^ (5th and 6th bits)
  int divisor = 8 / bits;

  // Resize host_data if necessary
  if (size % divisor != 0)
  {
    int new_size = size + (divisor - size % divisor);
    host_data = (char*) realloc(host_data, new_size * sizeof(char));
    for (int i = size; i < new_size; i++)
    {
      host_data[i] = 0;  // Padding with zeroes
    }
    size = new_size;
  }

  *msg_size = size / divisor;
  char* msg = (char*) malloc(*msg_size * sizeof(char));

  for (int i = 0; i < *msg_size; i++)
  {
    msg[i] = 0;
  }

  for (int i = 0; i < divisor; i++)
  {
    for (int j = 0; j < *msg_size; j++)
    {
      msg[j] |= (host_data[i + j * divisor] & ((int)powl(2, bits) - 1)) << (bits * i);
    }
  }

  return msg;
}


begin_declarations
  declare_string("stegv3");
  declare_string("stegv2");
end_declarations




int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  const char* file_data;
  int file_size = -1;

  foreach_memory_block(context->iterator, block) 
  {
    file_data = block->fetch_data(block);
    if (file_size == -1)
    {
      file_size = block->size;
    }
  }

  char* png_ident = (char*) calloc(4, 1);

  for (int i = 0; i < 4; i++)
  {
    png_ident[i] = file_data[i];
  }

  if (strcmp(png_ident, "‰PNG") != 0)
  {
    return ERROR_SUCCESS;
  }

  int width, height, channels;
  unsigned char* img = stbi_load_from_memory(
      file_data, file_size, &width, &height, &channels, 0);

  if (img == NULL)
  {
    printf("Failed to load image from memory\n");
    return;
  }

  int size = width * height * channels;
  int msg_size;
  char* message = decode_message(img, size, &msg_size);


  if (strcmp(message, "stegv3") == 0)
  {
    yr_set_string("true", module_object, "stegv3");
  }
  else if (strcmp(message, "stegv2") == 0)
  {
    yr_set_string("true", module_object, "stegv2");
  }
  else
  {
    yr_set_string("false", module_object, "stegv3");
    yr_set_string("false", module_object, "stegv2");
  }

  stbi_image_free(img);
  free(message);

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}