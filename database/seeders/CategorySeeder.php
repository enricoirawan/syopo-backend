<?php

namespace Database\Seeders;

use App\Models\Category;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class CategorySeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $categories = [
            [
                'name' => "Elektronik",
                'icon' => "category/Elektronik.webp",
                'childs' => ['Microwave', 'TV']
            ],
            [
                'name' => "Fashion Pria",
                'icon' => "category/Fashion-Pria.webp",
                'childs' => ['Kemeja', 'Jas']
            ],
            [
                'name' => "Fashion Wanita",
                'icon' => "category/Fashion-Wanita.webp",
                'childs' => ['Dress', 'Jas']
            ],
            [
                'name' => "Handphone",
                'icon' => "category/Handphone.webp",
                'childs' => ['Handphone', 'Anti Gores']
            ],
            [
                'name' => "Komputer & Laptop",
                'icon' => "category/Komputer-Laptop.webp",
                'childs' => ['Keyboard', 'Laptop']
            ],
            [
                'name' => "Makanan & Minuman",
                'icon' => "category/Makanan-Minuman.webp",
                'childs' => ['Makanan', 'Minuman']
            ],
        ];

        foreach ($categories as $categoryPayload) {
            $category = Category::create([
                "slug" => \Str::slug($categoryPayload['name']),
                "name" => $categoryPayload['name'],
                "icon" => $categoryPayload['icon'],
            ]);

            foreach ($categoryPayload['childs'] as $child) {
                $category->childs()->create([
                    "slug" => \Str::slug($child),
                    "name" => $child,
                ]);
            }
        }
    }
}
